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
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt;

use self::EventOperation as EO;
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChannelId(i64);

struct Client {
    account_id: i64,
    nick: String,
    channels: HashSet<ChannelId>,
}

#[derive(Copy, Clone, Debug)]
enum ErrorCode {
    // RFC1459, sending it for parse errors, and [..]
    UnknownError,

    // RFC1459, sending it for invalid message targets
    NoSuchNick,

    // RFC1459, sending it for invalid channel names
    InvalidChannel,

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
            ErrorCode::NoSuchNick => 403,
            ErrorCode::InvalidChannel => 403,
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

#[derive(Copy, Clone)]
struct ErrorResponse {
    code: ErrorCode,
    message: &'static str,
}

#[derive(Debug)]
enum EventOperation {
    SendMessage(String),
    JoinChannel(ChannelId),
    MessageChannel(ChannelId, String),
    MessageIndividual(String, String),
    Ping(String),
    Pong(String),
    ErrorReason(ErrorCode, &'static str),
    ErrorNickReason(ErrorCode, &'static str),
    ErrorWordReason(ErrorCode, String, &'static str),
    CloseClient,
}

impl System {
    fn new() -> Result<System, Error> {
        Ok(System {
            store: store::Store::new()?,
            clients: HashMap::new(),
            registering: HashMap::new(),
        })
    }

    fn work(&mut self, tokens: &HashSet<mio::Token>, connections: &mut serv::Connections) {
        // we expect there to be only one message per client
        let mut messages = Vec::with_capacity(tokens.len());

        for token in tokens {
            if let Some(client) = connections.get_mut(token) {
                if let Err(e) = take_messages(client, |message| messages.push((*token, message))) {
                    info!(
                        "{:?}: error handling a client's message buffer, bye: {:?}",
                        token, e
                    );
                    client.start_closing();
                }
            } else {
                unreachable!("server said there was work for a connection, but it's gone")
            }
        }

        let mut events = Vec::with_capacity(messages.len());

        for (token, message) in messages {
            self.translate_message(token, message, |token, event| events.push((token, event)))
                .expect("TODO");
        }

        let mut messages = Vec::with_capacity(events.len());

        // update clients and generate messages
        for (token, event) in events {
            let client = match self.clients.get_mut(&token) {
                Some(client) => client,
                None => continue,
            };

            match event {
                EO::JoinChannel(channel) => self.joined(
                    token,
                    unimplemented!(),
                    |_, _| unimplemented!(),
                    unimplemented!(),
                    unimplemented!(),
                ),
                EO::SendMessage(msg) => messages.push((token, msg)),
                EO::MessageIndividual(other_nick, msg) => messages.push((
                    token,
                    format!("{}!~@irc PRIVMSG {} :{}", client.nick, other_nick, msg),
                )),
                EO::MessageChannel(channel, _msg) => self.message_channel(channel),
                EO::Ping(symbol) => messages.push((token, format!("PING :{}", symbol))),
                EO::Pong(symbol) => messages.push((token, format!("PONG :{}", symbol))),
                EO::ErrorReason(code, msg) => {
                    messages.push((token, format!(":ircd {:03} :{}", code.into_numeric(), msg)))
                }
                EO::ErrorNickReason(code, msg) => unimplemented!(),
                EO::ErrorWordReason(code, word, msg) => unimplemented!(),
                EO::CloseClient => (),
            }
        }
    }

    fn translate_message<F: FnMut(mio::Token, EO)>(
        &mut self,
        token: mio::Token,
        message: Message,
        mut yield_event: F,
    ) -> Result<(), Error> {
        if self.clients.contains_key(&token) {
            self.translate_client_message(token, message, yield_event)?;
        } else if let Some(client) = self.translate_pre_auth(token, message, yield_event)? {
            assert!(
                self.registering.remove(&token).is_some(),
                "should be removing a registering client"
            );
            assert!(
                self.clients.insert(token, client).is_none(),
                "shouldn't be replacing an existing client"
            );
        }
        Ok(())
    }

    /// https://modern.ircdocs.horse/#connection-registration
    fn translate_pre_auth<F: FnMut(mio::Token, EO)>(
        &mut self,
        token: mio::Token,
        message: Message,
        mut yield_event: F,
    ) -> Result<Option<Client>, Error> {
        let mut state = self.registering.entry(token).or_default();

        match message.command {
            Command::CAP(_, cmd, ref arg, _)
                if CapSubCommand::LS == cmd && *arg == Some("302".to_string()) =>
            {
                // We support nothing, hahaha!
                yield_event(token, reply("CAP * LS :"));
            }
            Command::PASS(pass) => state.pass = Some(pass),
            Command::NICK(nick) => {
                if !valid_nick(&nick) {
                    yield_event(
                        token,
                        EO::ErrorNickReason(
                            ErrorCode::ErroneousNickname,
                            "invalid nickname; ascii letters, numbers, _. 2-12",
                        ),
                    );
                    return Ok(None);
                }

                state.nick = Some(nick);
                if state.ping == PreAuthPing::WaitingForNick {
                    state.ping = PreAuthPing::WaitingForPong;
                    yield_event(token, raw(format!("PING :{:08x}", state.ping_token.0)));
                }
            }
            Command::USER(ident, _mode, real_name) => state.gecos = Some((ident, real_name)),
            Command::PING(arg, _trail) => yield_event(token, EO::Pong(arg)),
            Command::PONG(ref arg, _)
                if PreAuthPing::WaitingForPong == state.ping
                    && u64::from_str_radix(arg, 16) == Ok(state.ping_token.0) =>
            {
                state.ping = PreAuthPing::Complete
            }
            Command::Raw(ref raw, ..) if is_http_verb(raw) => {
                info!("http command on channel: {:?}", raw);
                // TODO: is it worth sending them anything?
                yield_event(token, EO::CloseClient);
            }
            other => {
                yield_event(
                    token,
                    EO::ErrorReason(ErrorCode::NotRegistered, "invalid pre-auth command"),
                );
            }
        }

        if !state.is_client_preamble_done() {
            info!("waiting for more from client...");
            return Ok(None);
        }

        if state.pass.is_none() {
            yield_event(
                token,
                EO::ErrorReason(ErrorCode::PasswordMismatch, "You must provide a password"),
            );
            yield_event(token, EO::CloseClient);
            return Ok(None);
        }

        let nick = state.nick.as_ref().unwrap();

        let account_id = match self.store.user(nick, state.pass.as_ref().unwrap())? {
            Some(id) => id,
            None => {
                yield_event(
                    token,
                    EO::ErrorReason(
                        ErrorCode::PasswordMismatch,
                        concat!(
                            "Incorrect password for account. If you don't know",
                            " the password, you must use a different nick."
                        ),
                    ),
                );
                yield_event(token, EO::CloseClient);
                return Ok(None);
            }
        };

        // This is all legacy garbage. Trying to get any possible client to continue the connection.

        // Minimal hello.

        yield_event(token, raw(format!(":ircd 001 {} :Hi!", nick)));
        yield_event(token, raw(format!(":ircd 002 {} :This is IRC.", nick)));
        yield_event(token, raw(format!(":ircd 003 {} :This server is.", nick)));
        yield_event(token, raw(format!(":ircd 004 {} ircd badchat iZ s", nick)));
        yield_event(
            token,
            raw(format!(
                ":ircd 005 {} SAFELIST :are supported by this server",
                nick
            )),
        );

        // Minimal LUSERS

        yield_event(token, raw(format!(":ircd 251 {} :There are users.", nick)));
        yield_event(
            token,
            raw(format!(":ircd 254 {} 69 :channels formed", nick)),
        );
        yield_event(
            token,
            raw(format!(":ircd 255 {} :I have clients and servers.", nick)),
        );
        yield_event(
            token,
            raw(format!(
                ":ircd 265 {} 69 69 :Current local users are nice.",
                nick
            )),
        );

        // Minimal MOTD

        yield_event(
            token,
            raw(format!(
                ":ircd 422 {} :MOTDs haven't been cool for decades.",
                nick
            )),
        );

        yield_event(token, raw(format!(":{} MODE {0} :+iZ", nick)));

        Ok(Some(Client {
            account_id,
            nick: nick.to_string(),
            channels: HashSet::new(),
        }))
    }

    fn translate_client_message<F: FnMut(mio::Token, EO)>(
        &mut self,
        token: mio::Token,
        message: Message,
        mut yield_event: F,
    ) -> Result<(), Error> {
        match message.command {
            Command::JOIN(ref chan, ref keys, ref real_name)
                if keys.is_none() && real_name.is_none() =>
            {
                for chan in chan.split(',') {
                    let chan: &str = chan.trim();
                    if valid_channel(chan) {
                        yield_event(token, EO::JoinChannel(self.store.load_channel(chan)?))
                    } else {
                        yield_event(
                            token,
                            EO::ErrorWordReason(
                                ErrorCode::InvalidChannel,
                                "*".to_string(),
                                "channel name invalid",
                            ),
                        )
                    }
                }
            }
            Command::PRIVMSG(dest, msg) => {
                if dest.starts_with('#') && valid_channel(&dest) {
                    yield_event(
                        token,
                        EO::MessageChannel(self.store.load_channel(&dest)?, msg),
                    )
                } else if valid_nick(&dest) {
                    yield_event(token, EO::MessageIndividual(dest, msg))
                } else {
                    yield_event(
                        token,
                        EO::ErrorWordReason(
                            ErrorCode::NoSuchNick,
                            "*".to_string(),
                            "invalid channel or nickname",
                        ),
                    )
                }
            }
            Command::PING(arg, _) => yield_event(token, EO::Pong(arg)),
            Command::PONG(..) => (),
            other => {
                info!("invalid command: {:?}", other);
                yield_event(
                    token,
                    EO::ErrorNickReason(
                        ErrorCode::UnknownCommand,
                        "unrecognised or mis-parsed command",
                    ),
                );
            }
        }
        Ok(())
    }

    fn message_channel(&self, id: ChannelId) {
        for (other_token, other_client) in &self.clients {
            if !other_client.channels.contains(&id) {
                continue;
            }
            let op = raw(format!(":{}!~@irc PRIVMSG {} :{}", "nick", "dest", "msg"));
            unimplemented!("yield event {:?}", op);
        }
    }

    fn joined<F: FnMut(mio::Token, EO)>(
        &mut self,
        token: mio::Token,
        client: &Client,
        mut yield_event: F,
        chan: &String,
        id: &ChannelId,
    ) {
        // client joins, 322 topic, 333 topic who/time, 353 users, 366 end of names
        yield_event(token, raw(format!(":{}!~@irc JOIN {}", client.nick, chan)));
        yield_event(
            token,
            raw(format!(
                ":ircd 332 {} {} :This topic intentionally left blank.",
                client.nick, chan
            )),
        );
        // @: secret channel (+s)
        // TODO: client modes in a channel
        // TODO: splitting into multiple lines
        let names = self
            .clients
            .values()
            .filter(|client| client.channels.contains(&id))
            .map(|client| client.nick.as_ref())
            .collect::<Vec<&str>>()
            .join(" ");
        yield_event(
            token,
            raw(format!(
                ":ircd 353 {} @ {} :{} {}",
                client.nick, chan, client.nick, names
            )),
        );
        yield_event(
            token,
            raw(format!(":ircd 366 {} {} :</names>", client.nick, chan)),
        );
    }
}

fn take_messages<F: FnMut(irc_proto::Message)>(
    conn: &mut serv::Connection,
    mut yield_into: F,
) -> Result<(), Error> {
    loop {
        match line_to_message(conn.token, &mut conn.input_buffer) {
            Ok(Some(message)) => yield_into(message),
            Ok(None) => break,
            Err(response) => {
                conn.write_line(&format!(
                    ":ircd {} * :{}",
                    response.code.into_numeric(),
                    response.message,
                ))?;
            }
        }
    }

    if conn.input_buffer.len() > 10 * INPUT_LENGTH_LIMIT {
        conn.write_line(&format!(
            ":ircd {} * :Your input buffer is full, bye.",
            ErrorCode::LineTooLong.into_numeric(),
        ))?;

        // TODO: mmm, in theory, we might start processing a command at the middle of their input...
        // TODO: we should probably stop accepting input from people who are `closing` further up
        conn.input_buffer.clear();

        bail!("input buffer got too long");
    }

    Ok(())
}

fn line_to_message(
    token: mio::Token,
    input_buffer: &mut VecDeque<u8>,
) -> Result<Option<irc_proto::Message>, ErrorResponse> {
    let line = match pop_line(input_buffer) {
        PoppedLine::Done(line) => line,
        PoppedLine::NotReady => return Ok(None),
        PoppedLine::TooLong => {
            return Err(ErrorResponse {
                code: ErrorCode::LineTooLong,
                message: "Your message was discarded as it was too long",
            });
        }
    };

    let line = String::from_utf8(line).map_err(|parse_error| {
        debug!("{:?}: {:?}", token, parse_error);
        ErrorResponse {
            code: ErrorCode::BadCharEncoding,
            message: "Your line was discarded as it was not encoded using 'utf-8'",
        }
    })?;

    trace!("{:?}: line: {:?}", token, line);

    Ok(Some(line.parse().map_err(|parse_error| {
        debug!("{:?}: bad command: {:?} {:?}", token, line, parse_error);
        ErrorResponse {
            code: ErrorCode::UnknownError,
            message: "Unable to parse your input as any form of message",
        }
    })?))
}

fn is_http_verb(word: &str) -> bool {
    for verb in &["get", "connect", "post", "put", "delete", "patch"] {
        if word.eq_ignore_ascii_case(verb) {
            return true;
        }
    }

    false
}

enum PoppedLine {
    Done(Vec<u8>),
    NotReady,
    TooLong,
}

fn pop_line(buf: &mut VecDeque<u8>) -> PoppedLine {
    if let Some(pos) = buf.iter().position(|&b| b'\n' == b) {
        let drain = buf.drain(..pos);

        if pos > INPUT_LENGTH_LIMIT {
            // drain is dropped here, removing the data
            return PoppedLine::TooLong;
        }
        let mut vec: Vec<u8> = drain.collect();
        assert_eq!(Some(b'\n'), buf.pop_front());
        while vec.ends_with(&[b'\r']) {
            vec.pop();
        }
        PoppedLine::Done(vec)
    } else {
        PoppedLine::NotReady
    }
}

fn valid_channel(chan: &str) -> bool {
    if !chan.starts_with('#') {
        return false;
    }

    valid_nick(&chan[1..])
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

fn reply<S: fmt::Display>(whole: S) -> EO {
    EO::SendMessage(format!(":ircd {}", whole))
}

fn raw<S: ToString>(whole: S) -> EO {
    EO::SendMessage(whole.to_string())
}

fn main() -> Result<(), Error> {
    env_logger::Builder::new().parse("trace").init();

    let mut system = System::new()?;

    Ok(
        serv::serve_forever(|tokens, connections| system.work(tokens, connections))
            .with_context(|_| format_err!("running server"))?,
    )
}
