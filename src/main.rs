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

use failure::Error;
use failure::ResultExt;
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

#[derive(Debug)]
enum Req {
    JoinChannel(String),
    MessageChannel(String, String),
    MessageIndividual(String, String),
    Ping(String),
    Pong(String),
    CloseClient,
}

#[derive(Debug, Copy, Clone)]
enum ClientError {
    Die,
    ErrorReason(ErrorCode, &'static str),
    ErrorNickReason(ErrorCode, &'static str),
    ErrorWordReason(ErrorCode, &'static str, &'static str),
}

enum PreAuthOp {
    Waiting,
    Complete(Client),
    Ping(String),
    Pong(String),
    Error(ClientError),

    /// Mmm, no. We should extend ClientError with a proper ::Die.
    FatalError(ClientError),
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
                messages.extend(take_messages(client).into_iter().map(|r| (*token, r)));
            } else {
                unreachable!("server said there was work for a connection, but it's gone")
            }
        }

        let mut output = Vec::with_capacity(messages.len());

        for (token, message) in messages {
            let message = match message {
                Ok(message) => message,
                Err(e) => {
                    output.push(self.render_error(e, token));
                    continue;
                }
            };

            // I don't like this nested error handling. None of the collect() stuff works 'cos we
            // want to maintain order, and process everything. The main purpose was to simplify
            // translate_event, which hasn't happened. Maybe nest into the `Req`?

            if self.clients.contains_key(&token) {
                match self.translate_client_message(message) {
                    Ok(events) => {
                        for event in events {
                            match self.translate_event(token, event) {
                                Ok(lines) => output.extend(lines),
                                Err(e) => output.push(self.render_error(e, token)),
                            }
                        }
                    }
                    Err(e) => output.push(self.render_error(e, token)),
                }
            } else {
                match self.translate_pre_auth(token, message) {
                    PreAuthOp::Waiting => (),
                    PreAuthOp::Complete(client) => {
                        output.extend(
                            send_on_boarding(&client.nick)
                                .into_iter()
                                .map(|line| (token, line)),
                        );
                        assert!(
                            self.registering.remove(&token).is_some(),
                            "should be removing a registering client"
                        );
                        assert!(
                            self.clients.insert(token, client).is_none(),
                            "shouldn't be replacing an existing client"
                        );
                    }
                    PreAuthOp::Ping(ref label) => output.push((token, render_ping(label))),
                    PreAuthOp::Pong(ref label) => output.push((token, render_pong(label))),
                    PreAuthOp::Error(eo) => output.push(self.render_error(eo, token)),
                    PreAuthOp::FatalError(eo) => {
                        output.push(self.render_error(eo, token));
                        output.push(unimplemented!("die"))
                    }
                }
            }
        }

        for (token, line) in output {
            if let Some(conn) = connections.get_mut(&token) {
                if let Err(e) = conn.write_line(line) {
                    info!("{:?}: error sending normal message: {:?}", token, e);
                    conn.start_closing();
                }
            }
        }
    }

    fn translate_event(
        &mut self,
        token: mio::Token,
        event: Req,
    ) -> Result<Vec<(mio::Token, String)>, ClientError> {
        let mut output = Vec::with_capacity(4);

        let nick = self
            .clients
            .get(&token)
            .expect("invalid client")
            .nick
            .to_string();

        match event {
            Req::JoinChannel(ref channel) => output.extend(self.joined(token, channel)),
            Req::MessageIndividual(other_nick, msg) => output.push((
                token,
                format!("{}!~@irc PRIVMSG {} :{}", nick, other_nick, msg),
            )),
            Req::MessageChannel(ref channel, ref msg) => {
                output.extend(self.message_channel(token, &nick, channel, msg))
            }
            Req::Ping(ref symbol) => output.push((token, render_ping(symbol))),
            Req::Pong(ref symbol) => output.push((token, render_pong(symbol))),
            Req::CloseClient => unimplemented!(),
        }

        Ok(output)
    }

    fn render_error(&self, err: ClientError, us: mio::Token) -> (mio::Token, String) {
        (
            us,
            match err {
                ClientError::Die => unimplemented!("die"),
                ClientError::ErrorReason(code, msg) => {
                    format!(":ircd {:03} :{}", code.into_numeric(), msg)
                }
                ClientError::ErrorNickReason(code, msg) => {
                    let nick = self
                        .clients
                        .get(&us)
                        .map(|client| client.nick.as_str())
                        .unwrap_or("*");
                    format!(":ircd {:03} {} :{}", code.into_numeric(), nick, msg)
                }
                ClientError::ErrorWordReason(code, word, msg) => {
                    format!(":ircd {:03} {} :{}", code.into_numeric(), word, msg)
                }
            },
        )
    }

    /// https://modern.ircdocs.horse/#connection-registration
    fn translate_pre_auth(&mut self, token: mio::Token, message: Message) -> PreAuthOp {
        let mut state = self.registering.entry(token).or_default();

        match message.command {
            Command::PASS(pass) => state.pass = Some(pass),
            Command::NICK(nick) => {
                if !valid_nick(&nick) {
                    return PreAuthOp::Error(ClientError::ErrorNickReason(
                        ErrorCode::ErroneousNickname,
                        "invalid nickname; ascii letters, numbers, _. 2-12",
                    ));
                }

                state.nick = Some(nick);

                if state.ping == PreAuthPing::WaitingForNick {
                    state.ping = PreAuthPing::WaitingForPong;
                    return PreAuthOp::Ping(format!("{:08x}", state.ping_token.0));
                }
            }
            Command::USER(ident, _mode, real_name) => state.gecos = Some((ident, real_name)),
            Command::PING(arg, _trail) => return PreAuthOp::Pong(arg),
            Command::PONG(ref arg, _)
                if PreAuthPing::WaitingForPong == state.ping
                    && u64::from_str_radix(arg, 16) == Ok(state.ping_token.0) =>
            {
                state.ping = PreAuthPing::Complete
            }
            Command::Raw(ref raw, ..) if is_http_verb(raw) => {
                info!("http command on channel: {:?}", raw);
                // TODO: is it worth sending them anything?
                return PreAuthOp::Error(ClientError::Die);
            }
            other => {
                return PreAuthOp::Error(ClientError::ErrorReason(
                    ErrorCode::NotRegistered,
                    "invalid pre-auth command",
                ));
            }
        }

        if !state.is_client_preamble_done() {
            info!("waiting for more from client...");
            return PreAuthOp::Waiting;
        }

        if state.pass.is_none() {
            return PreAuthOp::FatalError(ClientError::ErrorReason(
                ErrorCode::PasswordMismatch,
                "You must provide a password",
            ));
        }

        let nick = state.nick.as_ref().unwrap();

        let account_id = match self.store.user(nick, state.pass.as_ref().unwrap()) {
            Some(id) => id,
            None => {
                return PreAuthOp::FatalError(ClientError::ErrorReason(
                    ErrorCode::PasswordMismatch,
                    concat!(
                        "Incorrect password for account. If you don't know",
                        " the password, you must use a different nick."
                    ),
                ));
            }
        };

        PreAuthOp::Complete(Client {
            account_id,
            nick: nick.to_string(),
            channels: HashSet::new(),
        })
    }

    fn translate_client_message(&mut self, message: Message) -> Result<Vec<Req>, ClientError> {
        match message.command {
            Command::JOIN(ref chan, ref keys, ref real_name)
                if keys.is_none() && real_name.is_none() =>
            {
                let mut joins = Vec::with_capacity(4);
                for chan in chan.split(',') {
                    let chan: &str = chan.trim();
                    if valid_channel(chan) {
                        joins.push(Req::JoinChannel(chan.to_string()))
                    } else {
                        return Err(ClientError::ErrorWordReason(
                            ErrorCode::InvalidChannel,
                            "*",
                            "channel name invalid",
                        ));
                    }
                }
                Ok(joins)
            }
            Command::PRIVMSG(dest, msg) => {
                if dest.starts_with('#') && valid_channel(&dest) {
                    Ok(vec![Req::MessageChannel(dest, msg)])
                } else if valid_nick(&dest) {
                    Ok(vec![Req::MessageIndividual(dest, msg)])
                } else {
                    Err(ClientError::ErrorWordReason(
                        ErrorCode::NoSuchNick,
                        "*",
                        "invalid channel or nickname",
                    ))
                }
            }
            Command::PING(arg, _) => Ok(vec![Req::Pong(arg)]),
            Command::PONG(..) => Ok(vec![]),
            other => {
                info!("invalid command: {:?}", other);
                Err(ClientError::ErrorNickReason(
                    ErrorCode::UnknownCommand,
                    "unrecognised or mis-parsed command",
                ))
            }
        }
    }

    fn message_channel(
        &mut self,
        us: mio::Token,
        our_nick: &str,
        channel: &str,
        msg: &str,
    ) -> Vec<(mio::Token, String)> {
        let mut output = Vec::with_capacity(32);

        let id = self.store.load_channel(channel);

        for (other_token, other_client) in &self.clients {
            if *other_token == us {
                // don't message ourselves
                continue;
            }

            if !other_client.channels.contains(&id) {
                continue;
            }

            output.push((
                *other_token,
                format!(":{}!~@irc PRIVMSG {} :{}", our_nick, channel, msg),
            ));
        }

        output
    }

    fn joined(&mut self, us: mio::Token, chan: &String) -> Vec<(mio::Token, String)> {
        let mut output = Vec::with_capacity(32);
        let id = self.store.load_channel(chan);

        let nick = {
            let client = self
                .clients
                .get_mut(&us)
                .expect("client generating event should exist");
            if !client.channels.insert(id) {
                return Vec::new();
            }
            client.nick.to_string()
        };

        // client joins, 322 topic, 333 topic who/time, 353 users, 366 end of names

        // send everyone the join message
        for (other_token, other_client) in &self.clients {
            if !other_client.channels.contains(&id) {
                continue;
            }
            output.push((*other_token, format!(":{}!~@irc JOIN {}", nick, chan)));
        }

        // send us some details
        output.push((
            us,
            format!(
                ":ircd 332 {} {} :This topic intentionally left blank.",
                nick, chan
            ),
        ));
        // @: secret channel (+s)
        // TODO: client modes in a channel

        const WRAP_AT: usize = 400;
        let mut blocks = Vec::with_capacity(8);
        let mut block = String::with_capacity(WRAP_AT + 32);
        for name in self
            .clients
            .values()
            .filter(|client| client.channels.contains(&id))
            .map(|client| client.nick.as_ref())
        {
            block.push_str(name);

            if block.len() > WRAP_AT {
                blocks.push(block.to_string());
                block.clear();
            }

            block.push(' ');
        }

        if let Some(val) = block.pop() {
            assert_eq!(
                ' ', val,
                "if the block has an end, it should end in a space"
            );
        }

        if !block.is_empty() {
            blocks.push(block);
        }

        for names in blocks {
            output.push((
                us,
                format!(":ircd 353 {} @ {} :{} {}", nick, chan, nick, names),
            ));
        }

        output.push((us, format!(":ircd 366 {} {} :</names>", nick, chan)));

        output
    }
}

fn take_messages(conn: &mut serv::Connection) -> Vec<Result<irc_proto::Message, ClientError>> {
    if conn.broken_input {
        match pop_line(&mut conn.input_buffer) {
            PoppedLine::Done(_) | PoppedLine::TooLong => {
                conn.broken_input = false;
            }
            PoppedLine::NotReady => {
                conn.input_buffer.clear();
                return Vec::new();
            }
        }
    }

    let mut output = Vec::with_capacity(4);
    loop {
        match line_to_message(conn.token, &mut conn.input_buffer) {
            Ok(Some(message)) => output.push(Ok(message)),
            Ok(None) => break,
            Err(response) => output.push(Err(response)),
        }
    }

    if conn.input_buffer.len() > 10 * INPUT_LENGTH_LIMIT {
        output.push(Err(ClientError::ErrorReason(
            ErrorCode::LineTooLong,
            "Your input buffer is full.",
        )));

        conn.broken_input = true;
        conn.input_buffer.clear();
    }

    output
}

fn render_ping(label: &str) -> String {
    format!("PING :{}", label)
}

fn render_pong(label: &str) -> String {
    format!("PONG :{}", label)
}

fn send_on_boarding<D: fmt::Display>(nick: D) -> Vec<String> {
    let mut output = Vec::with_capacity(16);

    // This is all legacy garbage. Trying to get any possible client to continue the connection.

    // Minimal hello.
    output.push(format!(":ircd 001 {} :Hi!", nick));
    output.push(format!(":ircd 002 {} :This is IRC.", nick));
    output.push(format!(":ircd 003 {} :This server is.", nick));
    output.push(format!(":ircd 004 {} ircd badchat iZ s", nick));
    output.push(format!(
        ":ircd 005 {} SAFELIST :are supported by this server",
        nick
    ));

    // Minimal LUSERS
    output.push(format!(":ircd 251 {} :There are users.", nick));
    output.push(format!(":ircd 254 {} 69 :channels formed", nick));
    output.push(format!(":ircd 255 {} :I have clients and servers.", nick));
    output.push(format!(
        ":ircd 265 {} 69 69 :Current local users are nice.",
        nick
    ));

    // Minimal MOTD
    output.push(format!(
        ":ircd 422 {} :MOTDs haven't been cool for decades.",
        nick
    ));

    output.push(format!(":{} MODE {0} :+iZ", nick));

    output
}

fn line_to_message(
    token: mio::Token,
    input_buffer: &mut VecDeque<u8>,
) -> Result<Option<irc_proto::Message>, ClientError> {
    let line = match pop_line(input_buffer) {
        PoppedLine::Done(line) => line,
        PoppedLine::NotReady => return Ok(None),
        PoppedLine::TooLong => {
            return Err(ClientError::ErrorReason(
                ErrorCode::LineTooLong,
                "Your message was discarded as it was too long",
            ));
        }
    };

    let line = String::from_utf8(line).map_err(|parse_error| {
        debug!("{:?}: {:?}", token, parse_error);
        ClientError::ErrorReason(
            ErrorCode::BadCharEncoding,
            "Your line was discarded as it was not encoded using 'utf-8'",
        )
    })?;

    trace!("{:?}: line: {:?}", token, line);

    Ok(Some(line.parse().map_err(|parse_error| {
        debug!("{:?}: bad command: {:?} {:?}", token, line, parse_error);
        ClientError::ErrorReason(
            ErrorCode::UnknownError,
            "Unable to parse your input as any form of message",
        )
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

fn main() -> Result<(), Error> {
    env_logger::Builder::new().parse("trace").init();

    let mut system = System::new()?;

    Ok(
        serv::serve_forever(|tokens, connections| system.work(tokens, connections))
            .with_context(|_| format_err!("running server"))?,
    )
}
