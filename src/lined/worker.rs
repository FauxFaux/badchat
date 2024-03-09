use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bunyarrs::vars_dbg;
use tokio::io::AsyncWriteExt;
use tokio::io::{split, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite};
use tokio::select;
use tokio_util::sync::CancellationToken;

use super::tempura::uuid;
use super::{Client, State};
use crate::{MessageIn, MessageOut, Uid};

pub fn run_worker<RW: AsyncRead + AsyncWrite + Send + 'static>(
    stream: RW,
    peer_addr: SocketAddr,
    state: Arc<State>,
) {
    let (reader, mut writer) = split(stream);
    let mut reader = tokio::io::BufReader::new(reader);

    let id = Uid(uuid());
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    state.clients.lock().expect("poisoned").insert(
        id,
        Client {
            peer_addr,
            write: tx,
        },
    );

    let local_cancel = CancellationToken::new();

    let state_for_write = Arc::clone(&state);
    let local_cancel_for_write = local_cancel.clone();

    tokio::spawn(async move {
        let logger = bunyarrs::Bunyarr::with_name("read-worker");
        if let Err(_) = state
            .inbound_tx
            .send((id, MessageIn::Connected(peer_addr)))
            .await
        {
            logger.warn((), "unable to notify of connection, aborting");
            return;
        }
        loop {
            // read_until_limit isn't cancel safe (the reader will have been partially consumed);
            // we must drop the reader if we are cancelled
            let read = select! {
                _ = local_cancel.cancelled() => break,
                read = read_until_limit(&mut reader, 4096) => read,
            };
            let buf = match read {
                Ok(buf) => buf,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    logger.debug(vars_dbg! { id, peer_addr }, "client closed connection");
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                    logger.info(vars_dbg! { id, peer_addr }, "client overflowed");
                    let _irrelevant_as_breaking = state.inbound_tx.send((id, MessageIn::Overflow));
                    break;
                }
                Err(err) => {
                    logger.warn(
                        vars_dbg! { id, peer_addr, err },
                        "client read failed with unexpected error",
                    );
                    break;
                }
            };

            // they've gone away, so stop accepting messages from them
            if !state.clients.lock().expect("poisoned").contains_key(&id) {
                break;
            }

            let Ok(buf) = String::from_utf8(buf) else {
                if let Err(_) = state.inbound_tx.send((id, MessageIn::InvalidUtf8)).await {
                    break;
                }
                continue;
            };
            if let Err(_) = state.inbound_tx.send((id, MessageIn::Data(buf))).await {
                break;
            }
        }

        // we can get here because we were cancelled or errored;
        // we must drop the reader, as it may be in an unexpected state
        drop(reader);

        let _ = state.inbound_tx.send((id, MessageIn::Closed)).await;
        local_cancel.cancel();
    });

    let state = state_for_write;
    let local_cancel = local_cancel_for_write;

    tokio::spawn(async move {
        let logger = bunyarrs::Bunyarr::with_name("write-worker");
        let mut flush = true;
        loop {
            let read = select! {
                _ = local_cancel.cancelled() => break,
                read = rx.recv() => read,
            };
            let Some(bytes) = read else {
                break;
            };
            match bytes {
                MessageOut::Data(bytes) => match writer.write_all(bytes.as_bytes()).await {
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                        break;
                    }
                    Err(err) => {
                        logger.warn(vars_dbg! { id, peer_addr, err }, "write failed");
                        break;
                    }
                },
                MessageOut::FlushAndClose => break,
                MessageOut::Terminate => {
                    flush = false;
                    break;
                }
            }
        }
        if flush {
            if let Err(err) = writer.flush().await {
                logger.info(
                    vars_dbg! { id, peer_addr, err },
                    "flush during shutdown failed",
                );
            }
            if let Err(err) = writer.shutdown().await {
                logger.info(vars_dbg! { id, peer_addr, err }, "shutdown failed");
            }
        }
        let _ = state.inbound_tx.send((id, MessageIn::Closed));
        drop(writer);
        local_cancel.cancel();
    });
}

async fn read_until_limit(
    mut reader: impl AsyncBufRead + Unpin,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::<u8>::with_capacity(limit);
    loop {
        let seen = reader.fill_buf().await?;
        if seen.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let (found, end) = match seen.iter().position(|&b| b == b'\n') {
            Some(end) => (true, end),
            None => (false, seen.len()),
        };
        buf.extend_from_slice(&seen[..end]);
        reader.consume(end);
        if found {
            // Consume the newline
            reader.consume(1);
            break;
        }
        if buf.len() > limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
    }

    Ok(buf)
}
