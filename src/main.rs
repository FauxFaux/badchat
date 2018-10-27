extern crate cast;
extern crate env_logger;
#[macro_use]
extern crate failure;
extern crate irc_proto;
#[macro_use]
extern crate log;
extern crate mio;
extern crate pbkdf2;
extern crate rand;
extern crate rusqlite;
extern crate rustls;
extern crate vecio;

mod serv;
mod store;

use std::collections::HashMap;
use std::collections::VecDeque;

use failure::Error;
use failure::ResultExt;
use irc_proto::CapSubCommand;
use irc_proto::Command;
use irc_proto::Message;
use rand::Rng;

type ConnId = mio::Token;

const INPUT_LENGTH_LIMIT: usize = 4_096;

struct PingToken(u64);

impl Default for PingToken {
    fn default() -> Self {
        PingToken(::rand::thread_rng().gen())
    }
}

struct System {
    store: store::Store,
    registering: HashMap<ConnId, PreAuth>,
    clients: HashMap<ConnId, Client>,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum PreAuthPing {
    WaitingForNick,
    WaitingForPong,
    Complete,
}

#[derive(Default)]
struct PreAuth {
    nick: Option<String>,
    pass: Option<String>,
    gecos: Option<(String, String)>,
    wants_cap: bool,
    ping: PreAuthPing,
    ping_token: PingToken,
}

impl PreAuth {
    fn is_client_preamble_done(&self) -> bool {
        self.gecos.is_some() && self.nick.is_some() && PreAuthPing::Complete == self.ping
    }
}

impl Default for PreAuthPing {
    fn default() -> Self {
        PreAuthPing::WaitingForNick
    }
}

struct Client {
    account_id: i64,
    nick: String,
}

#[derive(Copy, Clone, Debug)]
enum ErrorCode {
    // RFC1459, sending it for parse errors, and [..]
    UnknownError,

    // "length truncated" in aircd. Like with encoding, we're just rejecting
    LineTooLong,

    // RFC1459, but we also send it for some parse errors
    UnknownCommand,

    // RFC1459, sent for internal errors processing commands
    FileError,

    // RFC1459, possibly used as intended!
    ErroneousNickname,

    // RFC1459, including invalid pre-auth command parsing
    NotRegistered,

    // RFC1459, including pass missing
    PasswordMismatch,

    // KineIRCd. Most IRCds pass-through. I don't agree.
    BadCharEncoding,
}

impl ErrorCode {
    fn into_numeric(self) -> u16 {
        match self {
            ErrorCode::UnknownError => 400,
            ErrorCode::LineTooLong => 419,
            ErrorCode::UnknownCommand => 421,
            ErrorCode::FileError => 424,
            ErrorCode::ErroneousNickname => 432,
            ErrorCode::NotRegistered => 451,
            ErrorCode::PasswordMismatch => 451,
            ErrorCode::BadCharEncoding => 980,
        }
    }
}

impl System {
    fn new() -> Result<System, Error> {
        Ok(System {
            store: store::Store::new()?,
            clients: HashMap::new(),
            registering: HashMap::new(),
        })
    }

    fn work(&mut self, connections: &mut serv::Connections) {
        for (_token, conn) in connections {
            if let Err(e) = self.process_commands(conn) {
                error!("failed processing commands: {:?}", e);
                if let Err(e) = conn.write_line(&format!(
                    ":ircd {} * :server error",
                    ErrorCode::FileError.into_numeric()
                )) {
                    error!("..and couldn't tell them, so bye: {:?}", e);
                    conn.start_closing();
                }
            }
        }
    }

    fn process_commands(&mut self, conn: &mut serv::Connection) -> Result<(), Error> {
        while let Some(line) = pop_line(&mut conn.input_buffer) {
            let line = match String::from_utf8(line) {
                Ok(line) => line,
                Err(_) => {
                    conn.write_line(&format!(
                        ":ircd {} * :utf-8 only please",
                        ErrorCode::BadCharEncoding.into_numeric()
                    ))?;
                    continue;
                }
            };

            trace!("line: {:?}: {:?}", conn.token, line);

            let message: irc_proto::Message = match line.parse() {
                Ok(message) => message,
                Err(e) => {
                    debug!("bad command: {:?} {:?}", line, e);
                    // not a great error code here.
                    // Maybe we should send 400 BAD REQUEST^W^W ERR_UNKNOWN_ERROR.
                    conn.write_line(&format!(
                        ":ircd {} * :parse error",
                        ErrorCode::UnknownError.into_numeric(),
                    ))?;
                    continue;
                }
            };

            if let Some(client) = self.clients.get(&conn.token) {
                self.handle_client_message(conn, client, message)?;
            } else {
                if let Some(done) = self.handle_pre_auth(conn, message)? {
                    self.registering.remove(&conn.token);
                    self.clients.insert(conn.token, done);
                }
            }
        }

        if conn.input_buffer.len() > INPUT_LENGTH_LIMIT {
            conn.write_line(&format!(
                ":ircd {} * :message too long",
                ErrorCode::LineTooLong.into_numeric(),
            ))?;
        }

        Ok(())
    }

    /// https://modern.ircdocs.horse/#connection-registration
    fn handle_pre_auth(
        &mut self,
        conn: &mut serv::Connection,
        message: Message,
    ) -> Result<Option<Client>, Error> {
        let mut state = self.registering.entry(conn.token).or_default();

        match message.command {
            Command::CAP(_, cmd, ref arg, _)
                if CapSubCommand::LS == cmd && *arg == Some("302".to_string()) =>
            {
                // We support nothing, hahaha!
                conn.write_line(":ircd CAP * LS :")?;
            }
            Command::PASS(pass) => state.pass = Some(pass),
            Command::NICK(nick) => {
                if !valid_nick(&nick) {
                    conn.write_line(&format!(
                        ":ircd {} * :invalid nickname; ascii letters, numbers, _. 2-12",
                        ErrorCode::ErroneousNickname.into_numeric()
                    ))?;
                    return Ok(None);
                }

                state.nick = Some(nick);
                if state.ping == PreAuthPing::WaitingForNick {
                    state.ping = PreAuthPing::WaitingForPong;
                    conn.write_line(&format!("PING :{:08x}", state.ping_token.0))?;
                }
            }
            Command::USER(ident, _mode, real_name) => state.gecos = Some((ident, real_name)),
            Command::PING(ref token, _) => send_pong(conn, token)?,
            Command::PONG(ref token, _)
                if PreAuthPing::WaitingForPong == state.ping
                    && u64::from_str_radix(token, 16) == Ok(state.ping_token.0) =>
            {
                state.ping = PreAuthPing::Complete
            }
            Command::Raw(ref raw, ..) if is_http_verb(raw) => {
                info!("http command on channel: {:?}", raw);
                // TODO: is it worth sending them anything?
                conn.start_closing();
            }
            other => {
                info!("invalid pre-auth command: {:?}", other);
                conn.write_line(&format!(
                    ":ircd {} * :invalid pre-auth command",
                    ErrorCode::NotRegistered.into_numeric()
                ))?;
            }
        }

        if !state.is_client_preamble_done() {
            info!("waiting for more from client...");
            return Ok(None);
        }

        if state.pass.is_none() {
            conn.write_line(&format!(
                ":ircd {} * :You must provide a password",
                ErrorCode::PasswordMismatch.into_numeric()
            ))?;
            conn.start_closing();
            return Ok(None);
        }

        let nick = state.nick.as_ref().unwrap();

        let account_id = match self.store.user(nick, state.pass.as_ref().unwrap())? {
            Some(id) => id,
            None => {
                conn.write_line(&format!(
                    concat!(
                        ":ircd {} * :Incorrect password for account. If you don't know",
                        " the password, you must use a different nick."
                    ),
                    ErrorCode::PasswordMismatch.into_numeric()
                ))?;
                conn.start_closing();
                return Ok(None);
            }
        };

        // This is all legacy garbage. Trying to get any possible client to continue the connection.

        // Minimal hello.

        conn.write_line(format!(":ircd 001 {} :Hi!", nick))?;
        conn.write_line(format!(":ircd 002 {} :This is IRC.", nick))?;
        conn.write_line(format!(":ircd 003 {} :This server is.", nick))?;
        conn.write_line(format!(":ircd 004 {} ircd badchat iZ s", nick))?;
        conn.write_line(format!(
            ":ircd 005 {} SAFELIST :are supported by this server",
            nick
        ))?;

        // Minimal LUSERS

        conn.write_line(format!(":ircd 251 {} :There are users.", nick))?;
        conn.write_line(format!(":ircd 254 {} 69 :channels formed", nick))?;
        conn.write_line(format!(":ircd 255 {} :I have clients and servers.", nick))?;
        conn.write_line(format!(
            ":ircd 265 {} 69 69 :Current local users are nice.",
            nick
        ))?;

        // Minimal MOTD

        conn.write_line(format!(
            ":ircd 422 {} :MOTDs haven't been cool for decades.",
            nick
        ))?;

        conn.write_line(format!(":{} MODE {0} :+iZ", nick))?;

        Ok(Some(Client {
            account_id,
            nick: nick.to_string(),
        }))
    }

    fn handle_client_message(
        &self,
        conn: &mut serv::Connection,
        client: &Client,
        message: Message,
    ) -> Result<(), Error> {
        match message.command {
            Command::PING(ref token, _) => send_pong(conn, token)?,
            Command::PONG(..) => (),
            other => {
                info!("invalid command: {:?}", other);
                conn.write_line(&format!(
                    ":ircd {} {} ? :unrecognised or mis-parsed command: {:?}",
                    ErrorCode::UnknownCommand.into_numeric(),
                    client.nick,
                    other,
                ))?;
            }
        }
        Ok(())
    }
}

fn send_pong(conn: &mut serv::Connection, token: &str) -> Result<(), Error> {
    // TODO: validate the token isn't insane
    conn.write_line(format!("PONG :{}", token))?;
    Ok(())
}

fn is_http_verb(word: &str) -> bool {
    for verb in &["get", "connect", "post", "put", "delete", "patch"] {
        if word.eq_ignore_ascii_case(verb) {
            return true;
        }
    }

    false
}

fn pop_line(buf: &mut VecDeque<u8>) -> Option<Vec<u8>> {
    if let Some(pos) = buf.iter().position(|&b| b'\n' == b) {
        let mut vec: Vec<u8> = buf.drain(..pos).collect();
        assert_eq!(Some(b'\n'), buf.pop_front());
        while vec.ends_with(&[b'\r']) {
            vec.pop();
        }
        Some(vec)
    } else {
        None
    }
}

fn valid_nick(nick: &str) -> bool {
    if nick.len() <= 1 || nick.len() >= 12 {
        return false;
    }

    if nick.contains(|c| !valid_nick_char(c)) {
        return false;
    }

    if !nick.chars().next().unwrap().is_ascii_alphabetic() {
        return false;
    }

    true
}

fn valid_nick_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_".contains(c)
}

fn main() -> Result<(), Error> {
    env_logger::Builder::new().parse("trace").init();

    let mut system = System::new()?;

    Ok(serv::serve_forever(|connections| system.work(connections))
        .with_context(|_| format_err!("running server"))?)
}
