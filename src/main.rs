extern crate cast;
extern crate env_logger;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
extern crate mio;
extern crate pbkdf2;
extern crate rand;
extern crate rusqlite;
extern crate rustls;
extern crate vecio;

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt;

use failure::Error;
use failure::ResultExt;
use rand::Rng;

use self::ids::ChannelName;
use self::ids::HostMask;
use self::ids::Nick;
use self::proto::Command;
use self::proto::ParsedMessage as Message;

mod ids;
mod proto;
mod serv;
mod store;

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
    users: HashMap<UserId, User>,
    next_user_id: u64,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum PreAuthPing {
    WaitingForNick,
    WaitingForPong,
    Complete,
}

#[derive(Default)]
struct PreAuth {
    nick: Option<Nick>,
    pass: Option<String>,
    gecos: Option<(String, String)>,
    sending_caps: bool,
    ping: PreAuthPing,
    ping_token: PingToken,
}

impl PreAuth {
    fn is_client_preamble_done(&self) -> bool {
        self.gecos.is_some()
            && self.nick.is_some()
            && PreAuthPing::Complete == self.ping
            && !self.sending_caps
    }
}

impl Default for PreAuthPing {
    fn default() -> Self {
        PreAuthPing::WaitingForNick
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AccountId(i64);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChannelId(i64);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserId(u64);

#[derive(Debug)]
struct Client {
    account_id: AccountId,
    default_user: UserId,
    users: HashSet<UserId>,
}

#[derive(Debug)]
struct User {
    nick: Nick,
    host_mask: HostMask,
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

    // irv3.1, using as intended, but maybe don't have the full mandatory support
    InvalidCapCommand,

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
            ErrorCode::InvalidCapCommand => 410,
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
    JoinChannel(ChannelName),
    MessageChannel(ChannelName, String),
    MessageIndividual(Nick, String),
    Ping(String),
    Pong(String),
}

#[derive(Debug, Copy, Clone)]
enum ClientError {
    Die,
    FatalReason(ErrorCode, &'static str),
    ErrorReason(ErrorCode, &'static str),
    ErrorNickReason(ErrorCode, &'static str),
    ErrorWordReason(ErrorCode, &'static str, &'static str),
    ErrorNickWordReason(ErrorCode, &'static str, &'static str),
}

enum PreAuthOp {
    Waiting,
    Complete((AccountId, User)),
    Ping(String),
    Pong(String),
    CapList,
    Error(ClientError),
}

#[derive(Copy, Clone, Debug)]
enum FromTo {
    ServerToClient(mio::Token),
    ServerToUser(UserId),
    UserToUser(UserId, UserId),
}

#[derive(Clone, Debug)]
struct Output {
    from_to: FromTo,
    tags: (),
    cmd_and_args: String,

    /// Mmm. Trying to simplify 99% of the code which doesn't care.
    then_close: bool,
}

fn u<S: ToString>(from: UserId, to: UserId, cmd_and_args: S) -> Output {
    Output {
        from_to: FromTo::UserToUser(from, to),
        tags: (),
        cmd_and_args: cmd_and_args.to_string(),
        then_close: false,
    }
}

const UID_SERVER: UserId = UserId(0);

impl System {
    fn new() -> Result<System, Error> {
        Ok(System {
            store: store::Store::new()?,
            clients: HashMap::new(),
            users: HashMap::new(),
            next_user_id: UID_SERVER.0 + 1,
            registering: HashMap::new(),
        })
    }

    fn work(&mut self, tokens: &HashSet<mio::Token>, connections: &mut serv::Connections) {
        let mut output = Vec::with_capacity(4 * tokens.len());

        for token in tokens {
            self.work_one(
                *token,
                connections
                    .get_mut(token)
                    .expect("server said there was work for a connection, but it's gone"),
                &mut output,
            );
        }

        for Output {
            from_to,
            tags: (),
            cmd_and_args,
            then_close,
        } in output
        {
            enum Dest {
                Default(mio::Token),
                An(mio::Token),
                None,
            };

            let (from, to) = match from_to {
                FromTo::UserToUser(from, to) => (from, to),
                other => unimplemented!("from_to: {:?}", other),
            };

            let mut dest = Dest::None;

            let src = match self.users.get(&from) {
                Some(src) => src,
                None => unimplemented!("missing user.. disconnected, or server"),
            };

            for (token, client) in &self.clients {
                if client.default_user == to {
                    dest = Dest::Default(*token);
                }
            }

            match dest {
                Dest::Default(token) => {
                    if let Some(conn) = connections.get_mut(&token) {
                        let line = format!(":{}!~@. {}", src.nick, cmd_and_args);
                        if let Err(e) = conn.write_line(line) {
                            info!("{:?}: error sending normal message: {:?}", token, e);
                            conn.start_closing();
                        } else if then_close {
                            conn.start_closing();
                        }
                    }
                }
                _ => unimplemented!("unsupported dest"),
            }
        }
    }

    fn work_one(&mut self, us: mio::Token, conn: &mut serv::Conn, output: &mut Vec<Output>) -> () {
        for message in take_messages(conn) {
            let message = match message {
                Ok(message) => message,
                Err(e) => {
                    unimplemented!(
                        "need a way to directly return errors to the client: {:?}",
                        e
                    );
                }
            };

            output.extend(if self.clients.contains_key(&us) {
                self.work_client(us, message)
            } else {
                self.work_pre_auth(us, message)
                    .into_iter()
                    .map(|(fatal, msg)| Output {
                        from_to: FromTo::ServerToClient(us),
                        tags: (),
                        cmd_and_args: msg,
                        then_close: fatal,
                    })
                    .collect()
            });
        }
    }

    fn work_client(&mut self, us: mio::Token, message: Message) -> Vec<Output> {
        let client = self.clients.get(&us).expect("just checked");
        assert_eq!(0, client.users.len(), "TODO: code cannot handle sub users");

        let user_id = match message.source_nick() {
            Ok(Some(source_nick)) => {
                let user = match self.users.get(&client.default_user) {
                    Some(user) => user,
                    None => unimplemented!("invalid default user?"),
                };

                if user.nick != source_nick {
                    return vec![u(
                        UID_SERVER,
                        client.default_user,
                        format!(
                            "{:03} :no such user",
                            ErrorCode::ErroneousNickname.into_numeric()
                        ),
                    )];
                }

                // TODO: else block here
                client.default_user
            }
            Ok(None) => client.default_user,
            Err(_err) => {
                return vec![u(
                    UID_SERVER,
                    client.default_user,
                    format!(
                        "{:03} :invalid hostmask nickname",
                        ErrorCode::ErroneousNickname.into_numeric()
                    ),
                )];
            }
        };

        let mut output = Vec::with_capacity(4);

        match unpack_command(message.command()) {
            Ok(reqs) => {
                for req in reqs {
                    output.extend(self.work_req(user_id, req));
                }
            }
            Err(e) => {
                let (then_close, cmd_and_args) = render_error(e);
                output.push(Output {
                    from_to: FromTo::ServerToUser(user_id),
                    tags: (),
                    cmd_and_args,
                    then_close,
                })
            }
        }

        output
    }

    fn work_req(&mut self, us: UserId, req: Req) -> Vec<Output> {
        self.translate_event(us, req)
    }

    // TODO: Clearly this should be a Result<String, String>
    fn work_pre_auth(&mut self, us: mio::Token, message: Message) -> Vec<(bool, String)> {
        match self.translate_pre_auth(us, message) {
            PreAuthOp::Waiting => vec![],
            PreAuthOp::Complete((account_id, client)) => self
                .on_board(us, account_id, client)
                .into_iter()
                .map(|m| (false, m))
                .collect(),
            PreAuthOp::Ping(ref label) => vec![(false, render_ping(label))],
            PreAuthOp::Pong(ref label) => vec![(false, render_pong(label))],
            PreAuthOp::CapList => vec![(false, "CAP * LS :".to_string())],
            PreAuthOp::Error(eo) => vec![render_error(eo)],
        }
    }

    fn translate_event(&mut self, us: UserId, event: Req) -> Vec<Output> {
        let mut output = Vec::with_capacity(4);

        match event {
            Req::JoinChannel(ref channel) => output.extend(self.joined(us, channel)),
            Req::MessageIndividual(other_nick, msg) => {
                let to = match self.lookup_user(&other_nick) {
                    Some(user_id) => user_id,
                    None => {
                        return vec![u(
                            UID_SERVER,
                            us,
                            format!("{:03} :no such user", ErrorCode::NoSuchNick.into_numeric()),
                        )];
                    }
                };
                output.push(u(us, to, format!("PRIVMSG {} :{}", other_nick, msg)))
            }
            Req::MessageChannel(ref channel, ref msg) => {
                output.extend(self.message_channel(us, channel, msg))
            }
            Req::Ping(ref symbol) => output.push(u(UID_SERVER, us, render_ping(symbol))),
            Req::Pong(ref symbol) => output.push(u(UID_SERVER, us, render_pong(symbol))),
        }

        output
    }

    fn lookup_user(&self, nick: &Nick) -> Option<UserId> {
        self.users
            .iter()
            .find(|(_, u)| u.nick == *nick)
            .map(|(id, _)| *id)
    }

    /// https://modern.ircdocs.horse/#connection-registration
    fn translate_pre_auth(&mut self, token: mio::Token, message: Message) -> PreAuthOp {
        let mut state = self.registering.entry(token).or_default();

        match message.command() {
            Ok(Command::CapLs(_version)) => {
                state.sending_caps = true;
                return PreAuthOp::CapList;
            }
            Ok(Command::CapEnd) => {
                state.sending_caps = false;
            }
            Ok(Command::Pass(pass)) => state.pass = Some(pass.to_string()),
            Ok(Command::Nick(nick)) => {
                state.nick = Some(match Nick::new(nick) {
                    Ok(nick) => nick,
                    Err(_reason) => {
                        return PreAuthOp::Error(ClientError::ErrorNickReason(
                            ErrorCode::ErroneousNickname,
                            "invalid nickname; ascii letters, numbers, _. 2-12",
                        ));
                    }
                });

                if state.ping == PreAuthPing::WaitingForNick {
                    state.ping = PreAuthPing::WaitingForPong;
                    return PreAuthOp::Ping(format!("{:08x}", state.ping_token.0));
                }
            }
            Ok(Command::User(ident, _mode, real_name)) => {
                state.gecos = Some((ident.to_string(), real_name.to_string()))
            }
            Ok(Command::Ping(arg)) => return PreAuthOp::Pong(arg.to_string()),
            Ok(Command::Pong(ref arg))
                if PreAuthPing::WaitingForPong == state.ping
                    && u64::from_str_radix(arg, 16) == Ok(state.ping_token.0) =>
            {
                state.ping = PreAuthPing::Complete
            }
            Ok(Command::Other(ref raw, ..)) if is_http_verb(raw) => {
                info!("http command on channel: {:?}", raw);
                // TODO: is it worth sending them anything?
                return PreAuthOp::Error(ClientError::Die);
            }
            Ok(Command::CapUnknown) => {
                return PreAuthOp::Error(ClientError::ErrorNickWordReason(
                    ErrorCode::InvalidCapCommand,
                    "*",
                    "invalid cap command",
                ));
            }
            _other => {
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
            return PreAuthOp::Error(ClientError::FatalReason(
                ErrorCode::PasswordMismatch,
                concat!(
                    "You must provide a password. ",
                    "For an unregistered nick, any password is fine! ",
                    "I'll just make you a new account."
                ),
            ));
        }

        let nick = state.nick.as_ref().unwrap().clone();

        let account_id = AccountId(match self.store.user(&nick, state.pass.as_ref().unwrap()) {
            Some(id) => id,
            None => {
                return PreAuthOp::Error(ClientError::FatalReason(
                    ErrorCode::PasswordMismatch,
                    concat!(
                        "Incorrect password for account. If you don't know",
                        " the password, you must use a different nick."
                    ),
                ));
            }
        });

        PreAuthOp::Complete((
            account_id,
            User {
                nick,
                host_mask: HostMask::new(),
                channels: HashSet::new(),
            },
        ))
    }

    fn message_channel(&mut self, us: UserId, channel: &ChannelName, msg: &str) -> Vec<Output> {
        let mut output = Vec::with_capacity(32);

        let id = self.store.load_channel(channel);

        for (other_id, other_user) in &self.users {
            if *other_id == us {
                // don't message ourselves
                continue;
            }

            if !other_user.channels.contains(&id) {
                continue;
            }

            output.push(u(us, *other_id, format!("PRIVMSG {} :{}", channel, msg)));
        }

        output
    }

    fn on_board(&mut self, token: mio::Token, account_id: AccountId, user: User) -> Vec<String> {
        let on_boarding = send_on_boarding(&user.nick);

        assert!(
            self.registering.remove(&token).is_some(),
            "should be removing a registering client"
        );

        let new_user = UserId(self.next_user_id);
        self.users.insert(new_user, user);
        self.next_user_id += 1;

        let client = Client {
            account_id,
            default_user: new_user,
            users: HashSet::new(),
        };

        assert!(
            self.clients.insert(token, client).is_none(),
            "shouldn't be replacing an existing client"
        );

        on_boarding
    }

    fn joined(&mut self, us: UserId, chan: &ChannelName) -> Vec<Output> {
        let mut output = Vec::with_capacity(32);
        let id = self.store.load_channel(chan);

        let nick = {
            let user = self
                .users
                .get_mut(&us)
                .expect("user generating event should exist");
            if !user.channels.insert(id) {
                return vec![];
            }
            user.nick.to_string()
        };

        // client joins, 322 topic, 333 topic who/time, 353 users, 366 end of names

        // send everyone the join message
        for (other_id, other_user) in &self.users {
            if !other_user.channels.contains(&id) {
                continue;
            }
            output.push(u(us, *other_id, format!("JOIN {}", chan)));
        }

        // send us some details
        output.push(u(
            UID_SERVER,
            us,
            format!(
                "332 {} {} :This topic intentionally left blank.",
                nick, chan
            ),
        ));
        // @: secret channel (+s)
        // TODO: client modes in a channel

        for names in wrapped(
            self.users
                .values()
                .filter(|user| user.channels.contains(&id))
                .map(|user| user.nick.as_ref()),
        ) {
            output.push(u(
                UID_SERVER,
                us,
                format!("353 {} @ {} :{} {}", nick, chan, nick, names),
            ));
        }

        output.push(u(
            UID_SERVER,
            us,
            format!("366 {} {} :</names>", nick, chan),
        ));

        output
    }
}

fn unpack_command(command: Result<Command, &'static str>) -> Result<Vec<Req>, ClientError> {
    match command {
        Ok(Command::Join(ref chan, ref keys, ref real_name))
            if keys.is_none() && real_name.is_none() =>
        {
            let mut joins = Vec::with_capacity(4);
            for chan in chan.split(',') {
                let chan = match ChannelName::new(chan.trim().to_string()) {
                    Ok(chan) => chan,
                    Err(_reason) => {
                        return Err(ClientError::ErrorWordReason(
                            ErrorCode::InvalidChannel,
                            "*",
                            "channel name invalid",
                        ));
                    }
                };
                joins.push(Req::JoinChannel(chan));
            }
            Ok(joins)
        }
        Ok(Command::Privmsg(dest, msg)) => {
            if dest.starts_with('#') {
                match ChannelName::new(dest) {
                    Ok(chan) => Ok(vec![Req::MessageChannel(chan, msg.to_string())]),
                    Err(_reason) => Err(ClientError::ErrorWordReason(
                        ErrorCode::NoSuchNick,
                        "*",
                        "invalid channel",
                    )),
                }
            } else {
                match Nick::new(dest) {
                    Ok(nick) => Ok(vec![Req::MessageIndividual(nick, msg.to_string())]),
                    Err(_reason) => Err(ClientError::ErrorWordReason(
                        ErrorCode::NoSuchNick,
                        "*",
                        "invalid channel or nickname",
                    )),
                }
            }
        }
        Ok(Command::Ping(arg)) => Ok(vec![Req::Pong(arg.to_string())]),
        Ok(Command::Pong(..)) => Ok(vec![]),
        other => {
            info!("invalid command: {:?}", other);
            Err(ClientError::ErrorNickReason(
                ErrorCode::UnknownCommand,
                "unrecognised or mis-parsed command",
            ))
        }
    }
}

fn render_error(err: ClientError) -> (bool, String) {
    // TODO: Arguments for error codes are dependent on the code, making this ALL WRONG
    match err {
        ClientError::Die => (
            true,
            "999 * :You angered us in some way, sorry. Bye.".to_string(),
        ),
        ClientError::ErrorNickReason(code, msg) | ClientError::ErrorReason(code, msg) => {
            (false, format!("{:03} * :{}", code.into_numeric(), msg))
        }
        ClientError::FatalReason(code, msg) => {
            (true, format!("{:03} * :{}", code.into_numeric(), msg))
        }
        ClientError::ErrorNickWordReason(code, word, msg) => (
            false,
            format!(":ircd {:03} * {} :{}", code.into_numeric(), word, msg),
        ),
        ClientError::ErrorWordReason(code, word, msg) => (
            false,
            format!(":ircd {:03} {} :{}", code.into_numeric(), word, msg),
        ),
    }
}

fn wrapped<'i, I: IntoIterator<Item = &'i str>>(it: I) -> Vec<String> {
    const WRAP_AT: usize = 400;

    let mut blocks = Vec::with_capacity(8);
    let mut block = String::with_capacity(WRAP_AT + 32);
    for name in it {
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

    blocks
}

fn take_messages(conn: &mut serv::Conn) -> Vec<Result<Message, ClientError>> {
    if conn.input.broken {
        match pop_line(&mut conn.input.buf) {
            PoppedLine::Done(_) | PoppedLine::TooLong => {
                conn.input.broken = false;
            }
            PoppedLine::NotReady => {
                conn.input.buf.clear();
                return Vec::new();
            }
        }
    }

    let mut output = Vec::with_capacity(4);
    loop {
        match line_to_message(conn.net.token, &mut conn.input.buf) {
            Ok(Some(message)) => output.push(Ok(message)),
            Ok(None) => break,
            Err(response) => output.push(Err(response)),
        }
    }

    if conn.input.buf.len() > 10 * INPUT_LENGTH_LIMIT {
        output.push(Err(ClientError::ErrorReason(
            ErrorCode::LineTooLong,
            "Your input buffer is full.",
        )));

        conn.input.broken = true;
        conn.input.buf.clear();
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
) -> Result<Option<Message>, ClientError> {
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

    Ok(Some(proto::parse_message(line).map_err(|parse_error| {
        debug!("{:?}: bad command: {:?}", token, parse_error);
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

fn main() -> Result<(), Error> {
    env_logger::Builder::new().parse("trace").init();

    let mut system = System::new()?;

    Ok(
        serv::serve_forever(|tokens, connections| system.work(tokens, connections))
            .with_context(|_| format_err!("running server"))?,
    )
}
