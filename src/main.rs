extern crate cast;
extern crate env_logger;
#[macro_use]
extern crate failure;
extern crate irc;
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
use irc::proto::CapSubCommand;
use irc::proto::Command;
use irc::proto::Message;
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

#[derive(Default)]
struct PreAuth {
    nick: Option<String>,
    pass: Option<String>,
    gecos: Option<(String, String)>,
    wants_cap: bool,
    ping: bool,
    ping_token: PingToken,
}

impl PreAuth {
    fn is_client_preamble_done(&self) -> bool {
        self.gecos.is_some() && self.nick.is_some()
    }
}

struct Client {
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

            let message: irc::proto::Message = match line.parse() {
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

            if let Some(client) = self.clients.get_mut(&conn.token) {
                unimplemented!("client");
            } else {
                self.handle_pre_auth(conn, message)?;
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
    ) -> Result<(), Error> {
        let mut state = self.registering.entry(conn.token).or_default();

        match message.command {
            Command::CAP(_, cmd, ref arg, _)
                if CapSubCommand::LS == cmd && *arg == Some("302".to_string()) =>
            {
                // We support nothing, hahaha!
                conn.write_line(":ircd CAP * LS :")?;
            }
            Command::PASS(pass) => state.pass = Some(pass),
            Command::NICK(nick) => state.nick = Some(nick),
            Command::USER(ident, _mode, real_name) => state.gecos = Some((ident, real_name)),
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
            return Ok(());
        }

        if state.pass.is_none() {
            conn.write_line(&format!(
                ":ircd {} * :You must provide a password",
                ErrorCode::PasswordMismatch.into_numeric()
            ))?;
            conn.start_closing();
            return Ok(());
        }

        match self
            .store
            .user(state.nick.as_ref().unwrap(), state.pass.as_ref().unwrap())?
        {
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
                return Ok(());
            }
        };

        Ok(())
    }
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

fn main() -> Result<(), Error> {
    env_logger::Builder::new().parse("trace").init();

    let mut system = System::new()?;

    Ok(serv::serve_forever(|connections| system.work(connections))
        .with_context(|_| format_err!("running server"))?)
}
