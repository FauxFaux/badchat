use crate::bad::proto::{parse_message, Command, ParsedMessage};
use crate::bad::{err, OutCommand, PingToken};
use anyhow::Result;
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::{sleep, Instant};

use crate::lined::{read_message, FromLined, MessageIn, MessageOut, ToLined, Uid};

struct Client {
    inp: Sender<MessageIn>,
}

struct State {
    clients: Mutex<HashMap<Uid, Client>>,
    resolver: Arc<TokioAsyncResolver>,
}

pub async fn drive(mut inp: Receiver<FromLined>, out: Sender<ToLined>) -> Result<()> {
    let state = Arc::new(State {
        clients: Mutex::new(HashMap::with_capacity(64)),
        resolver: Arc::new(TokioAsyncResolver::tokio_from_system_conf()?),
    });

    let mut js = JoinSet::new();

    while let Some(msg) = inp.recv().await {
        match msg {
            FromLined::Message(uid, msg) => match msg {
                MessageIn::Connected(host) => {
                    let state = Arc::clone(&state);
                    let out = out.clone();

                    let (cli, clo) = tokio::sync::mpsc::channel(1);
                    state.clients.lock().await.insert(uid, Client { inp: cli });

                    js.spawn(work_client(uid, state, out, clo, host));
                }
                other => {
                    if let Some(client) = state.clients.lock().await.get(&uid) {
                        client.inp.send(other).await?;
                    }
                }
            },
        }
    }

    while let Some(task) = js.join_next().await {
        task??;
    }

    Ok(())
}

async fn work_client(
    uid: Uid,
    state: Arc<State>,
    mut out: Sender<ToLined>,
    mut inp: Receiver<MessageIn>,
    host: SocketAddr,
) -> Result<()> {
    #[derive(Default)]
    struct Pre {
        nick: Option<String>,
        gecos: Option<(String, String)>,
        host: Option<String>,
        ping_success: bool,
    }
    let mut pre = Pre::default();

    let resolver = Arc::clone(&state.resolver);
    let mut resolve = tokio::spawn(async move { resolver.reverse_lookup(host.ip()).await });

    let deadline = Instant::now() + Duration::from_secs(5);
    let deadline = sleep(deadline - Instant::now());

    let mut initial_ping_sent = false;
    let initial_symbol = PingToken::default();

    while let Some(command) = regular_message(&mut inp, uid, &mut out).await {
        match command.command().expect("handled in 'regular_message'") {
            Command::Ping(_) => unreachable!("handled in 'regular_message'"),
            Command::Nick(nick) => {
                pre.nick = Some(nick.to_string());
            }
            Command::User(a, _b, c) => {
                pre.gecos = Some((a.to_string(), c.to_string()));
            }
            // maybe we should handle pong with an invalid argument
            Command::Pong(token) if u64::from_str_radix(token, 16) == Ok(initial_symbol.0) => {
                pre.ping_success = true;
            }
            // TODO: CAP LS, CAP END, PASS
            _ => {
                send_out(
                    &mut out,
                    uid,
                    err::unknown_command((), "", "unknown command for early pre-auth"),
                )
                .await
                .ok_or_else(|| anyhow!("gone away"))?;
                continue;
            }
        }

        // fall through to here on any valid command
        if !initial_ping_sent {
            initial_ping_sent = true;
            send_out(
                &mut out,
                uid,
                OutCommand::new("PING", &[format!("{:08x}", initial_symbol.0)]),
            )
            .await
            .ok_or_else(|| anyhow!("gone away"))?;
        }

        if pre.nick.is_some() && pre.gecos.is_some() && pre.ping_success {
            break;
        }
    }

    pre.host = Some(match resolve.await? {
        Ok(name) => match name.iter().next() {
            Some(name) => name.0.to_utf8(),
            None => host.ip().to_string(),
        },
        Err(_) => host.ip().to_string(),
    });

    while let Some(msg) = inp.recv().await {
        println!("client {:?} got {:?}", uid, msg);
    }

    Ok(())
}

async fn regular_message(
    inp: &mut Receiver<MessageIn>,
    uid: Uid,
    out: &mut Sender<ToLined>,
) -> Option<ParsedMessage> {
    loop {
        match inp.recv().await? {
            MessageIn::Data(data) => match parse_message(&data) {
                Ok(msg) => match msg.command() {
                    Ok(Command::Ping(token)) => {
                        send_out(out, uid, OutCommand::new("PONG", &[token])).await?;
                    }
                    Ok(_) => return Some(msg),
                    Err(err) => {
                        info!("parse error (command): {data:?} -> {err:?}");
                        send_out(out, uid, err::unknown_error((), "", err)).await?;
                    }
                },
                Err(err) => {
                    info!("parse error (line): {data:?} -> {err:?}");
                    send_out(out, uid, err::unknown_error((), "", err)).await?;
                }
            },
            MessageIn::Overflow => {
                send_out(
                    out,
                    uid,
                    err::line_too_long((), "message too long; dropped"),
                )
                .await?;
            }
            MessageIn::InvalidUtf8 => {
                send_out(
                    out,
                    uid,
                    err::bad_char_encoding((), "", "invalid utf-8 in line; dropped"),
                )
                .await?;
            }
            MessageIn::Connected(_) => unreachable!("handled to start this worker"),
            MessageIn::Closed => return None,
        }
    }
}

async fn send_out(out: &mut Sender<ToLined>, uid: Uid, cmd: OutCommand) -> Option<()> {
    out.send(ToLined::Message(uid, MessageOut::Data(cmd.render())))
        .await
        .ok()
}
