use crate::bad::proto::{parse_message, Command};
use anyhow::Result;
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::lined::{FromLined, MessageIn, MessageOut, ToLined, Uid};

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
    out: Sender<ToLined>,
    mut inp: Receiver<MessageIn>,
    host: SocketAddr,
) -> Result<()> {
    #[derive(Default)]
    struct Pre {
        nick: Option<String>,
        gecos: Option<(String, String)>,
        host: Option<String>,
    }
    let mut pre = Pre::default();

    let resolver = Arc::clone(&state.resolver);
    let mut resolve = tokio::spawn(async move { resolver.reverse_lookup(host.ip()).await });

    let mut deadline = tokio::time::sleep(tokio::time::Duration::from_secs(5));
    pin!(&mut resolve);
    loop {
        select! {
            res = &mut resolve => {
                pre.host = Some(match res? {
                    Ok(name) => match name.iter().next() {
                        Some(name) => name.0.to_utf8(),
                        None => host.ip().to_string(),
                    },
                    Err(_) => host.ip().to_string(),
                });
            }
            // TODO: work out how to pin a sleep
            // _ = &mut deadline => break,
            msg = inp.recv() => {
                match msg {
                    Some(MessageIn::Data(data)) => {
                        let msg = parse_message(&data).expect("TODO: reply to client");
                        // TODO: reply to ping (outside?)
                        // TODO: ping them and check they respond
                        // TODO: ? means "return an error to client here"

                        match msg.command().expect("TODO: reply to client") {
                            Command::Nick(nick) => {
                                pre.nick = Some(nick.to_string());
                            }
                            Command::User(a, _b, c) => {
                                pre.gecos = Some((a.to_string(), c.to_string()));
                            }
                            _ => unimplemented!("ping, cap, pong, pass, etc."),
                        }
                    }
                    Some(MessageIn::Connected(_)) => unreachable!("handled to start this worker"),
                    Some(MessageIn::Overflow) => {
                        // TODO: error helper
                        out.send(ToLined::Message(
                            uid,
                            MessageOut::Data("Your message was too long".to_string()),
                        ))
                        .await?;
                    }
                    Some(MessageIn::InvalidUtf8) => {
                        // TODO: error helper
                        out.send(ToLined::Message(
                            uid,
                            MessageOut::Data("Your message contained invalid UTF-8".to_string()),
                        ))
                        .await?;
                    }
                    Some(MessageIn::Closed) => {
                        // TODO: cleanup?
                        break;
                    }
                    None => break,
                }
            }
        }
    }
    while let Some(msg) = inp.recv().await {
        println!("client {:?} got {:?}", uid, msg);
    }
    Ok(())
}
