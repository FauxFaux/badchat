use bunyarrs::vars_dbg;
use std::net::SocketAddr;
use std::ptr::write;
use std::sync::Arc;

use badchat::{decode, read_message, write_message, FromLined, MessageIn, ToLined};
use tokio::io::{split, AsyncBufReadExt, AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::State;

pub fn run_admin<RW: AsyncRead + AsyncWrite + Send + 'static>(
    stream: RW,
    peer_addr: SocketAddr,
    state: Arc<State>,
) {
    let (reader, mut writer) = split(stream);
    let mut reader = tokio::io::BufReader::new(reader);

    let state_for_write = Arc::clone(&state);
    let local_cancel = CancellationToken::new();
    let local_cancel_for_write = local_cancel.clone();

    tokio::spawn(async move {
        let mut buf = Vec::with_capacity(4096);
        loop {
            let inp = select! {
                _ = local_cancel.cancelled() => break,
                read = read_message::<ToLined>(&mut buf, &mut reader) => read,
            };

            let inp = match inp {
                Ok(inp) => inp,
                Err(err) => {
                    state
                        .logger
                        .error(vars_dbg! { err }, "unable to read message");
                    break;
                }
            };
            match inp {
                ToLined::Message(id, msg) => {
                    let sent = {
                        let clients = state.clients.lock().expect("poison");
                        let Some(client) = clients.get(&id) else {
                            continue;
                        };
                        client.write.try_send(msg)
                    };

                    if let Err(_) = sent {
                        if let Err(err) = state.inbound_tx.send((id, MessageIn::Closed)).await {
                            state
                                .logger
                                .error(vars_dbg! { err }, "unable to notify of closure");
                            break;
                        }
                    }
                }
            }
        }

        local_cancel.cancel();
    });

    let state = state_for_write;
    let local_cancel = local_cancel_for_write;

    tokio::spawn(async move {
        let mut inbound_rx = state.inbound_rx.lock().await;
        loop {
            let recv = select! {
                _ = local_cancel.cancelled() => break,
                recv = inbound_rx.recv() => recv,
            };

            let (client, msg) = match recv {
                Some(recv) => recv,
                None => {
                    state.logger.error((), "inbound channel closed");
                    break;
                }
            };

            let msg = FromLined::Message(client, msg);

            let res = select! {
                _ = local_cancel.cancelled() => break,
                res = write_message(&mut writer, &msg) => res,
            };

            if let Err(err) = res {
                state
                    .logger
                    .error(vars_dbg! { err }, "unable to write message");
                break;
            }
        }

        local_cancel.cancel();
    });
}
