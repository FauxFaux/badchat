mod err;
mod ids;
mod pre;
mod proto;
mod store;
mod two;

use std::collections::HashMap;
use std::collections::HashSet;
use std::mem;
use std::net::Ipv6Addr;

use anyhow::Result;
use hickory_resolver::TokioAsyncResolver;
use rand::random;
use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinSet;

use super::lined::{read_message, write_message, FromLined, MessageIn, MessageOut, ToLined, Uid};

use super::in_map::MapBorrow;
use crate::bad::two::drive;
use ids::ChannelName;
use ids::HostMask;
use ids::Nick;
use proto::Command;
use proto::ParsedMessage as Message;
use store::Store;

type ConnId = Uid;

const INPUT_LENGTH_LIMIT: usize = 4_096;

#[derive(Debug, Copy, Clone)]
pub struct PingToken(u64);

impl Default for PingToken {
    fn default() -> Self {
        PingToken(random())
    }
}

type Clients = HashMap<ConnId, Client>;

struct Users {
    data: HashMap<UserId, User>,
    next: u64,
}

struct System {
    store: Store,
    clients: Clients,
    users: Users,

    resolver: TokioAsyncResolver,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PreAuthPing {
    WaitingForNick,
    WaitingForPong,
    Complete,
}

// TODO: maybe not Debug, or re-implement it?
#[derive(Debug, Clone)]
pub struct Pass {
    account: String,
    pass: String,
}

#[derive(Debug, Default)]
pub struct PreAuth {
    nick: Option<Nick>,
    pass: Option<Pass>,
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
enum Client {
    PreAuth {
        state: PreAuth,
        host: (),
    },
    Singleton {
        account_id: AccountId,
        user_id: UserId,
    },
    MultiAware {
        connection_account_id: AccountId,
        users: HashSet<UserId>,
    },
}

#[derive(Debug)]
struct User {
    nick: Nick,
    host_mask: HostMask,
    channels: HashSet<ChannelId>,
}

#[derive(Debug)]
enum Req {
    JoinChannel(ChannelName),
    MessageChannel(ChannelName, String),
    MessageIndividual(Nick, String),
    Pong(String),
}

#[derive(Copy, Clone, Debug)]
enum FromTo {
    LinkManagement(Uid),
    ServerToClient(Uid),
    ServerToUser(UserId),
    UserToUser(UserId, UserId),
}

#[derive(Clone, Debug)]
pub struct OutCommand {
    cmd: &'static str,
    args: Vec<String>,
}

#[derive(Clone, Debug)]
struct Output {
    from_to: FromTo,
    tags: (),
    cmd_and_args: OutCommand,

    /// Mmm. Trying to simplify 99% of the code which doesn't care.
    then_close: bool,
}

#[inline]
fn u<S: ToString, I: IntoIterator<Item = S>>(
    from: UserId,
    to: UserId,
    cmd: &'static str,
    args: I,
) -> Output {
    Output {
        from_to: FromTo::UserToUser(from, to),
        tags: (),
        cmd_and_args: OutCommand::new(cmd, args),
        then_close: false,
    }
}

#[inline]
fn s2u<S: ToString, I: IntoIterator<Item = S>>(to: UserId, cmd: &'static str, args: I) -> Output {
    Output {
        from_to: FromTo::ServerToUser(to),
        tags: (),
        cmd_and_args: OutCommand::new(cmd, args),
        then_close: false,
    }
}

impl System {
    fn new() -> Result<System> {
        let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()?;
        Ok(System {
            store: store::Store::new()?,
            clients: HashMap::new(),
            users: Users {
                data: HashMap::new(),
                next: 0,
            },

            resolver,
        })
    }

    async fn run(&mut self, mut inp: Receiver<FromLined>, out: Sender<ToLined>) -> Result<()> {
        while let Some(msg) = inp.recv().await {
            match msg {
                FromLined::Message(uid, msg_in) => {
                    match msg_in {
                        MessageIn::Data(text) => {
                            out.send(ToLined::Message(
                                uid,
                                MessageOut::Data(format!("hello, {text}")),
                            ))
                            .await?
                        }
                        _ => {
                            out.send(ToLined::Message(
                                uid,
                                MessageOut::Data(format!("not implemented")),
                            ))
                            .await?
                        }
                    };
                }
            }
        }
        Ok(())
    }
}

fn find_user(clients: &Clients, which: UserId) -> Uid {
    for (token, client) in clients {
        match client {
            Client::PreAuth { .. } => (),
            Client::Singleton { user_id, .. } => {
                if *user_id == which {
                    return *token;
                }
            }
            Client::MultiAware { .. } => unimplemented!("multi-aware client"),
        }
    }

    unimplemented!("no client has user_id: {:?}", which);
}

impl OutCommand {
    #[inline]
    fn new<S: ToString, I: IntoIterator<Item = S>>(cmd: &'static str, args: I) -> OutCommand {
        OutCommand {
            cmd,
            args: args.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    fn render(&self) -> String {
        if self.args.is_empty() {
            return self.cmd.to_string();
        }

        let mut out = String::with_capacity(self.cmd.len() + self.args.len() * 6);
        out.push_str(self.cmd);

        for arg in &self.args[..self.args.len() - 1] {
            out.push(' ');
            assert!(!arg.is_empty());
            assert!(!arg.starts_with(':'));
            assert!(!arg.contains(|c: char| c.is_whitespace()));
            out.push_str(&arg);
        }

        let last_arg = &self.args[self.args.len() - 1];

        out.push(' ');
        out.push(':');

        out.push_str(&last_arg);

        out
    }
}

fn work_client(
    store: &mut Store,
    users: &mut Users,
    us: Uid,
    mut client: MapBorrow<ConnId, Client>,
    message: Message,
) -> Vec<Output> {
    use pre::PreAuthOp;

    info!(
        "{:?}: work_client: {:?} - {:?}",
        us,
        client.as_ref(),
        message
    );

    match client.as_mut() {
        Client::PreAuth { state, .. } => match pre::work_pre_auth(&message, state) {
            PreAuthOp::Done => {
                let nick = state.nick.as_ref().unwrap().clone();

                let account_id = AccountId(match store.account(state.pass.as_ref().unwrap()) {
                    Some(id) => id,
                    None => {
                        return vec![Output {
                            from_to: FromTo::ServerToClient(us),
                            tags: (),
                            cmd_and_args: err::password_mismatch(
                                (),
                                concat!(
                                    "Incorrect password for account. If you don't know",
                                    " the password, you must use a different nick."
                                ),
                            ),
                            then_close: true,
                        }];
                    }
                });

                let existing_user =
                    users.data.iter().find_map(
                        |(id, u)| {
                            if nick == u.nick {
                                Some(*id)
                            } else {
                                None
                            }
                        },
                    );

                if existing_user.is_some() {
                    return vec![Output {
                        from_to: FromTo::ServerToClient(us),
                        tags: (),
                        cmd_and_args: err::nickname_in_use(
                            (),
                            &nick,
                            "That nickname is in use, and the rest of this code is TODO!",
                        ),
                        then_close: true,
                    }];
                }

                let user_id = UserId(users.next);
                users.next += 1;

                let (state, _) = match mem::replace(
                    client.as_mut(),
                    Client::Singleton {
                        account_id,
                        user_id,
                    },
                ) {
                    Client::PreAuth { state, host } => (state, host),
                    _ => unreachable!("it was match'd above and hasn't changed"),
                };

                let (ident_name, _real_name) = state.gecos.unwrap();
                let host = "";

                let on_boarding = send_on_boarding(&nick.to_string());

                users.data.insert(
                    user_id,
                    User {
                        nick,
                        host_mask: HostMask::new(&ident_name, &host),
                        channels: HashSet::new(),
                    },
                );

                on_boarding
                    .into_iter()
                    .map(|cmd_and_args| Output {
                        from_to: FromTo::ServerToUser(user_id),
                        tags: (),
                        cmd_and_args,
                        then_close: false,
                    })
                    .collect()
            }
            // So.. this is damn terrible. Instead of waiting with timers,
            // let's just send the client PINGs over and over again. Hah. Hah. Hah.
            PreAuthOp::Done => vec![Output {
                from_to: FromTo::LinkManagement(us),
                tags: (),
                cmd_and_args: OutCommand::new("PING", &["waiting-for-hostname"]),
                then_close: false,
            }],
            PreAuthOp::Output(messages) => messages
                .into_iter()
                .map(|cmd_and_args| Output {
                    from_to: FromTo::ServerToClient(us),
                    tags: (),
                    cmd_and_args,
                    then_close: false,
                })
                .collect(),
            PreAuthOp::Ping(symbol) => vec![Output {
                from_to: FromTo::LinkManagement(us),
                tags: (),
                cmd_and_args: OutCommand::new("PING", &[format!("{:08x}", symbol.0)]),
                then_close: false,
            }],
            PreAuthOp::Error(msg) => vec![Output {
                from_to: FromTo::ServerToClient(us),
                tags: (),
                cmd_and_args: msg,
                then_close: true,
            }],
        },
        Client::Singleton {
            account_id,
            user_id,
        } => work_single_client(store, users, *account_id, *user_id, message),
        Client::MultiAware { .. } => unimplemented!(),
    }
}

fn work_single_client(
    store: &mut Store,
    users: &mut Users,
    _account_id: AccountId,
    user_id: UserId,
    message: Message,
) -> Vec<Output> {
    let user_id = match message.source_nick() {
        Ok(Some(source_nick)) => {
            let user = match users.data.get(&user_id) {
                Some(user) => user,
                None => unimplemented!("invalid default user?"),
            };

            if user.nick != source_nick {
                return vec![Output {
                    from_to: FromTo::ServerToUser(user_id),
                    tags: (),
                    cmd_and_args: err::erroneous_nickname(
                        (),
                        source_nick.to_string(),
                        "no such user",
                    ),
                    then_close: false,
                }];
            }

            user_id
        }
        Ok(None) => user_id,
        Err(_err) => {
            return vec![Output {
                from_to: FromTo::ServerToUser(user_id),
                tags: (),
                cmd_and_args: err::erroneous_nickname(
                    (),
                    "*".to_string(),
                    "invalid hostmask nickname",
                ),
                then_close: false,
            }];
        }
    };

    match unpack_command(message.command()) {
        Ok(reqs) => reqs
            .into_iter()
            .flat_map(|req| work_req(store, users, user_id, req))
            .collect(),
        Err(cmd_and_args) => vec![Output {
            from_to: FromTo::ServerToUser(user_id),
            tags: (),
            cmd_and_args,
            then_close: false,
        }],
    }
}

fn work_req(store: &mut Store, users: &mut Users, us: UserId, req: Req) -> Vec<Output> {
    let mut output = Vec::with_capacity(4);

    match req {
        Req::JoinChannel(ref channel) => output.extend(joined(store, users, us, channel)),
        Req::MessageIndividual(other_nick, msg) => {
            let to = match lookup_user(users, &other_nick) {
                Some(user_id) => user_id,
                None => {
                    return vec![Output {
                        from_to: FromTo::ServerToUser(us),
                        tags: (),
                        cmd_and_args: err::no_such_nick((), other_nick.to_string(), "no such user"),
                        then_close: false,
                    }];
                }
            };
            output.push(u(us, to, "PRIVMSG", &[other_nick.to_string(), msg]));
        }
        Req::MessageChannel(ref channel, ref msg) => {
            output.extend(message_channel(store, users, us, channel, msg))
        }
        Req::Pong(_symbol) => (),
    }

    output
}

fn lookup_user(users: &Users, nick: &Nick) -> Option<UserId> {
    users
        .data
        .iter()
        .find(|(_, u)| u.nick == *nick)
        .map(|(id, _)| *id)
}

fn message_channel(
    store: &mut Store,
    users: &Users,
    us: UserId,
    channel: &ChannelName,
    msg: &str,
) -> Vec<Output> {
    let mut output = Vec::with_capacity(32);

    let id = store.load_channel(channel);

    for (other_id, other_user) in users.data.iter() {
        if *other_id == us {
            // don't message ourselves
            continue;
        }

        if !other_user.channels.contains(&id) {
            continue;
        }

        output.push(u(us, *other_id, "PRIVMSG", &[&channel.to_string(), msg]));
    }

    output
}

fn joined(store: &mut Store, users: &mut Users, us: UserId, chan: &ChannelName) -> Vec<Output> {
    let mut output = Vec::with_capacity(32);
    let id = store.load_channel(chan);

    let nick = {
        let user = users
            .data
            .get_mut(&us)
            .expect("user generating event should exist");
        if !user.channels.insert(id) {
            return vec![];
        }
        user.nick.to_string()
    };

    // client joins, 322 topic, 333 topic who/time, 353 users, 366 end of names

    // send everyone the join message
    for (other_id, other_user) in users.data.iter() {
        if !other_user.channels.contains(&id) {
            continue;
        }
        output.push(u(us, *other_id, "JOIN", &[chan]));
    }

    // send us some details
    output.push(s2u(
        us,
        "332",
        &[
            &nick,
            &chan.to_string(),
            "This topic intentionally left blank.",
        ],
    ));
    // @: secret channel (+s)
    // TODO: client modes in a channel

    for names in wrapped(
        users
            .data
            .values()
            .filter(|user| user.channels.contains(&id))
            .map(|user| user.nick.as_ref()),
    ) {
        output.push(s2u(
            us,
            "353",
            &[
                nick.to_string(),
                "@".to_string(),
                chan.to_string(),
                format!("{} {}", nick, names),
            ],
        ));
    }

    output.push(s2u(
        us,
        "366",
        &[nick, chan.to_string(), "</names>".to_string()],
    ));

    output
}

fn unpack_command(command: Result<Command, &'static str>) -> Result<Vec<Req>, OutCommand> {
    match command {
        Ok(Command::Join(ref chan, ref keys, ref real_name))
            if keys.is_none() && real_name.is_none() =>
        {
            let mut joins = Vec::with_capacity(4);
            for chan in chan.split(',') {
                let chan = chan.trim().to_string();
                let chan = match ChannelName::new(&chan) {
                    Ok(chan) => chan,
                    Err(_reason) => {
                        return Err(err::no_such_channel((), chan, "channel name invalid"));
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
                    Err(_reason) => Err(err::no_such_channel(
                        (),
                        dest.to_string(),
                        "invalid channel",
                    )),
                }
            } else {
                match Nick::new(dest) {
                    Ok(nick) => Ok(vec![Req::MessageIndividual(nick, msg.to_string())]),
                    Err(_reason) => Err(err::no_such_nick(
                        (),
                        dest.to_string(),
                        "invalid channel or nickname",
                    )),
                }
            }
        }
        Ok(Command::Ping(_)) => unreachable!("ping handled as link management"),
        Ok(Command::Pong(..)) => Ok(vec![]),
        other => {
            info!("invalid command: {:?}", other);
            Err(err::unknown_command(
                (),
                "*",
                "unrecognised or mis-parsed command",
            ))
        }
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

fn send_on_boarding(nick: &str) -> Vec<OutCommand> {
    let mut output = Vec::with_capacity(16);

    // This is all legacy garbage. Trying to get any possible client to continue the connection.

    // Minimal hello.
    output.push(OutCommand::new("001", &[nick, "Hi!"]));
    output.push(OutCommand::new("002", &[nick, "This is IRC."]));
    output.push(OutCommand::new("003", &[nick, "This server is."]));
    output.push(OutCommand::new("004", &[nick, "ircd badchat iZ s"]));
    output.push(OutCommand::new(
        "005",
        &[nick, "SAFELIST", "UTF8ONLY", "are supported by this server"],
    ));

    // Minimal LUSERS
    output.push(OutCommand::new("251", &[nick, "There are users."]));
    output.push(OutCommand::new("254", &[nick, "69", "channels formed"]));
    output.push(OutCommand::new(
        "255",
        &[nick, "I have clients and servers."],
    ));
    output.push(OutCommand::new(
        "265",
        &[nick, "69", "69", "Current local users are nice."],
    ));

    // Minimal MOTD
    output.push(OutCommand::new(
        "422",
        &[nick, "MOTDs haven't been cool for decades."],
    ));

    // TODO: should the user be setting this on themselves, not the server doing it?
    output.push(OutCommand::new("MODE", &[nick, "+iZ"]));

    output
}

fn line_to_message(token: Uid, line: &str) -> Result<Option<Message>, OutCommand> {
    Ok(Some(proto::parse_message(line).map_err(|parse_error| {
        debug!("{:?}: bad command: {:?}", token, parse_error);
        err::unknown_error((), "*", "Unable to parse your input as any form of message")
    })?))
}

pub async fn main() -> Result<()> {
    env_logger::Builder::new().parse_filters("trace").init();

    let mut system = System::new()?;

    let lined = TcpStream::connect((Ipv6Addr::LOCALHOST, 6766)).await?;
    let (read, mut write) = lined.into_split();
    let mut read = BufReader::new(read);

    let (from_lined_tx, mut from_lined_rx) = tokio::sync::mpsc::channel::<FromLined>(128);
    let (to_lined_tx, mut to_lined_rx) = tokio::sync::mpsc::channel::<ToLined>(128);

    let mut js = JoinSet::new();

    js.spawn(async move {
        let mut buf = Vec::with_capacity(4096 + 32);
        loop {
            let value = read_message(&mut buf, &mut read).await?;
            from_lined_tx.send(value).await?;
        }

        Ok::<(), anyhow::Error>(())
    });

    js.spawn(async move {
        while let Some(obj) = to_lined_rx.recv().await {
            write_message(&mut write, obj).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    js.spawn(async move { drive(from_lined_rx, to_lined_tx).await });

    while let Some(task) = js.join_next().await {
        task??;
    }

    Ok(())
}
