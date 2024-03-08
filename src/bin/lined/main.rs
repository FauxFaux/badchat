use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::{Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use bunyarrs::{vars, vars_dbg, Bunyarr};
use rustls_pemfile::{certs, rsa_private_keys};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{
    copy, sink, split, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt,
    BufStream,
};
use tokio::net::TcpListener;
use tokio::select;
use tokio::signal::unix::SignalKind;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use uuid::{Bytes, NoContext, Uuid};

#[derive(serde::Deserialize, Clone)]
struct Options {
    cert: PathBuf,
    key: PathBuf,
}

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

fn load_keys(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .next()
        .unwrap()
        .map(Into::into)
}

enum MessageIn {
    Data(String),
    Overflow,
    InvalidUtf8,
    Closed,
}

enum MessageOut {
    Data(String),
    Close,
}

struct State {
    inbound: tokio::sync::mpsc::Sender<(Uuid, MessageIn)>,
    clients: Mutex<HashMap<Uuid, Client>>,
    logger: Bunyarr,
}

struct Client {
    peer_addr: SocketAddr,
    write: tokio::sync::mpsc::Sender<MessageOut>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let logger = bunyarrs::Bunyarr::with_name("main");

    let options: Options = config::Config::builder()
        .add_source(config::Environment::with_prefix("LINED"))
        .build()?
        .try_deserialize()?;

    let ext_binds = [
        (Ipv6Addr::UNSPECIFIED, 6667, false),
        (Ipv6Addr::UNSPECIFIED, 6697, true),
    ];

    let int_binds = [(Ipv6Addr::LOCALHOST, 6766)];

    let mut reload = tokio::signal::unix::signal(SignalKind::hangup())?;
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(16);

    let state = Arc::new(State {
        clients: Mutex::new(HashMap::new()),
        inbound: inbound_tx,
        logger,
    });

    loop {
        let mut plain_servers = Vec::new();
        let mut tls_servers = Vec::new();
        // let mut admin_servers = Vec::new();
        for &(addr, port, tls) in &ext_binds {
            let cancel = CancellationToken::new();
            let cancel_clone = cancel.clone();
            if tls {
                tls_servers.push((
                    cancel,
                    tokio::spawn(tls_server(
                        options.clone(),
                        (addr, port).into(),
                        cancel_clone,
                        Arc::clone(&state),
                    )),
                ));
            } else {
                plain_servers.push((
                    cancel,
                    tokio::spawn(plain_server(
                        (addr, port).into(),
                        cancel_clone,
                        Arc::clone(&state),
                    )),
                ));
            }
        }
        for &(addr, port) in &int_binds {
            // admin_servers.push(tokio::spawn(admin_server(options.clone(), addr, port, false, reload.recv())));
        }

        select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = reload.recv() => {}
        }
        state.logger.info((), "pausing accepts for reload");

        for (cancel, server) in plain_servers.into_iter().chain(tls_servers.into_iter()) {
            cancel.cancel();
            server.await??;
        }

        state.logger.info((), "reloading");
    }

    Ok(())
}

async fn tls_server(
    options: Options,
    addr: SocketAddr,
    cancel: CancellationToken,
    state: Arc<State>,
) -> Result<()> {
    let certs = load_certs(&options.cert)?;
    let key = load_keys(&options.key)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(addr).await?;

    state.logger.info(vars! { addr }, "tls listen started");

    loop {
        let (stream, peer_addr) = select! {
            v = listener.accept() => v?,
            _ = cancel.cancelled() => break,
        };

        let acceptor = acceptor.clone();
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let stream = acceptor.accept(stream).await.expect("TODO");
            run_worker(stream, peer_addr, state);
        });
    }

    drop(acceptor);
    drop(listener);

    Ok(())
}

async fn plain_server(
    addr: SocketAddr,
    cancel: CancellationToken,
    state: Arc<State>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;

    state.logger.info(vars! { addr }, "plain listen started");

    loop {
        let (stream, peer_addr) = select! {
            v = listener.accept() => v?,
            _ = cancel.cancelled() => break,
        };

        let state = Arc::clone(&state);

        tokio::spawn(async move {
            run_worker(stream, peer_addr, state);
        });
    }

    Ok(())
}

fn run_worker<RW: AsyncRead + AsyncWrite + Send + 'static>(
    stream: RW,
    peer_addr: SocketAddr,
    state: Arc<State>,
) {
    let (reader, mut writer) = split(stream);
    let mut reader = tokio::io::BufReader::new(reader);

    let id = uuid();
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
        loop {
            let buf = match read_until_limit(&mut reader, 4096).await {
                Ok(buf) => buf,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    logger.debug(vars_dbg! { id, peer_addr }, "client closed connection");
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                    logger.info(vars_dbg! { id, peer_addr }, "client overflowed");
                    let _irrelevant_as_breaking =
                        state.inbound.send((id, MessageIn::Overflow)).await;
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
                if let Err(_) = state.inbound.send((id, MessageIn::InvalidUtf8)).await {
                    break;
                }
                continue;
            };
            if let Err(_) = state.inbound.send((id, MessageIn::Data(buf))).await {
                break;
            }
        }

        let _ = state.inbound.send((id, MessageIn::Closed)).await;
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
        let _ = state.inbound.send((id, MessageIn::Closed)).await;
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

fn uuid() -> Uuid {
    Uuid::new_v7(uuid::Timestamp::now(NoContext))
}
