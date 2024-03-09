use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use badchat::Uid;
use bunyarrs::vars_dbg;
use tokio::io::AsyncWriteExt;
use tokio::io::{split, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite};

use crate::tempura::uuid;
use crate::{Client, MessageIn, MessageOut, State};

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

    let state_for_write = Arc::clone(&state);

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
            let buf = match read_until_limit(&mut reader, 4096).await {
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

        let _ = state.inbound_tx.send((id, MessageIn::Closed)).await;
        drop(reader);
    });

    let state = state_for_write;

    tokio::spawn(async move {
        let logger = bunyarrs::Bunyarr::with_name("write-worker");
        loop {
            let Some(bytes) = rx.recv().await else {
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
                MessageOut::Close => break,
            }
        }
        let _ = state.inbound_tx.send((id, MessageIn::Closed));
        if let Err(err) = writer.shutdown().await {
            logger.info(vars_dbg! { id, peer_addr, err }, "shutdown failed");
        }
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
