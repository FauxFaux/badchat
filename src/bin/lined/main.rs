use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::io::{self, BufReader};
use std::net::{Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use bincode::de::{BorrowDecoder, Decoder};
use bincode::enc::Encoder;
use bincode::error::DecodeError;
use bunyarrs::{vars, vars_dbg, Bunyarr};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
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
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput,
              "no rsa keys found (only pkcs8 / BEGIN PRIVATE KEY, i.e. not pkcs1 / BEGIN RSA PRIVATE KEY, is supported)"))?
        .map(Into::into)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct Uid(Uuid);

impl bincode::Encode for Uid {
    fn encode<E: Encoder>(
        &self,
        e: &mut E,
    ) -> std::result::Result<(), bincode::error::EncodeError> {
        self.0.as_bytes().encode(e)
    }
}

impl bincode::Decode for Uid {
    fn decode<D: Decoder>(d: &mut D) -> std::result::Result<Self, bincode::error::DecodeError> {
        Ok(Uid(Uuid::from_bytes(<[u8; 16]>::decode(d)?)))
    }
}

impl<'de> bincode::BorrowDecode<'de> for Uid {
    fn borrow_decode<D: BorrowDecoder<'de>>(d: &mut D) -> std::result::Result<Self, DecodeError> {
        use bincode::Decode;
        Ok(Uid(Uuid::from_bytes(<[u8; 16]>::decode(d)?)))
    }
}

#[derive(bincode::Encode, bincode::Decode, Debug)]
enum MessageIn {
    Data(String),
    Connected(SocketAddr),
    Overflow,
    InvalidUtf8,
    Closed,
}

#[derive(bincode::Encode, bincode::Decode, Debug)]
enum Command {
    Message(Uid, MessageOut),
}

#[derive(bincode::Encode, bincode::Decode, Debug)]
enum MessageOut {
    Data(String),
    Close,
}

struct State {
    inbound_tx: tokio::sync::mpsc::Sender<(Uid, MessageIn)>,
    inbound_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(Uid, MessageIn)>>,
    clients: Mutex<HashMap<Uid, Client>>,
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

    let admin_binds = [(Ipv6Addr::LOCALHOST, 6766)];

    let mut reload = tokio::signal::unix::signal(SignalKind::hangup())?;
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(128);

    let state = Arc::new(State {
        clients: Mutex::new(HashMap::new()),
        inbound_tx,
        inbound_rx: tokio::sync::Mutex::new(inbound_rx),
        logger,
    });

    loop {
        let mut cancels = Vec::new();

        let mut tls_servers = FuturesUnordered::new();
        let mut plain_servers = FuturesUnordered::new();
        let mut admin_servers = FuturesUnordered::new();

        for &(addr, port, tls) in &ext_binds {
            let cancel = CancellationToken::new();
            cancels.push(cancel.clone());
            if tls {
                tls_servers.push(tls_server(
                    options.clone(),
                    (addr, port).into(),
                    cancel,
                    Arc::clone(&state),
                ));
            } else {
                plain_servers.push(plain_server(
                    (addr, port).into(),
                    cancel,
                    Arc::clone(&state),
                ));
            }
        }
        for &(addr, port) in &admin_binds {
            let cancel = CancellationToken::new();
            cancels.push(cancel.clone());
            admin_servers.push(admin_server(
                (addr, port).into(),
                cancel,
                Arc::clone(&state),
            ));
        }

        let then_break = select! {
            _ = tokio::signal::ctrl_c() => true,
            _ = reload.recv() => false,
            ret = plain_servers.next() => {
                ret.ok_or_else(|| anyhow::anyhow!("no plain servers"))??;
                bail!("unreachable: plain server returned without shutdown");
            },
            ret = tls_servers.next() => {
                ret.ok_or_else(|| anyhow::anyhow!("no tls servers"))??;
                bail!("unreachable: tls server returned without shutdown");
            },
            ret = admin_servers.next() => {
                ret.ok_or_else(|| anyhow::anyhow!("no admin servers"))??;
                bail!("unreachable: admin server returned without shutdown");
            },
        };

        if then_break {
            state.logger.info((), "ending accepts for shutdown");
        } else {
            state.logger.info((), "pausing accepts for reload");
        }

        for cancel in cancels {
            cancel.cancel();
        }

        while let Some(server) = plain_servers.next().await {
            server?;
        }

        while let Some(server) = tls_servers.next().await {
            server?;
        }

        while let Some(server) = admin_servers.next().await {
            server?;
        }

        if then_break {
            break;
        }

        state.logger.info((), "reloading");
    }

    // TODO: wait for (some) clients?
    state
        .logger
        .info((), "shutdown complete; killing remaining clients");

    Ok(())
}

async fn tls_server(
    options: Options,
    addr: SocketAddr,
    cancel: CancellationToken,
    state: Arc<State>,
) -> Result<()> {
    let certs = load_certs(&options.cert)
        .with_context(|| anyhow!("loading certs from {:?}", options.cert))?;
    let key =
        load_keys(&options.key).with_context(|| anyhow!("loading key from {:?}", options.key))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
        .with_context(|| anyhow!("setting up tls"))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| anyhow!("binding {addr:?} for tls"))?;

    state.logger.info(vars! { addr }, "tls listen started");

    loop {
        let (stream, peer_addr) = select! {
            v = listener.accept() => v?,
            _ = cancel.cancelled() => break,
        };

        add_keepalives(&stream)?;

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

        add_keepalives(&stream)?;

        let state = Arc::clone(&state);

        tokio::spawn(async move {
            run_worker(stream, peer_addr, state);
        });
    }

    Ok(())
}

async fn admin_server(
    addr: SocketAddr,
    cancel: CancellationToken,
    state: Arc<State>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;

    state.logger.info(vars! { addr }, "admin listen started");

    loop {
        let (stream, peer_addr) = select! {
            v = listener.accept() => v?,
            _ = cancel.cancelled() => break,
        };

        add_keepalives(&stream)?;

        let state = Arc::clone(&state);

        tokio::spawn(async move {
            run_admin(stream, peer_addr, state);
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

fn run_admin<RW: AsyncRead + AsyncWrite + Send + 'static>(
    stream: RW,
    peer_addr: SocketAddr,
    state: Arc<State>,
) {
    let (reader, mut writer) = split(stream);
    let mut reader = tokio::io::BufReader::new(reader);

    let state_for_write = Arc::clone(&state);

    tokio::spawn(async move {
        let mut buf = String::with_capacity(1024);
        loop {
            buf.clear();
            let num = reader.read_line(&mut buf).await.expect("todo");
            if num == 0 {
                break;
            }
            println!("{}", buf);
        }
    });

    let state = state_for_write;
    tokio::spawn(async move {
        loop {
            let mut inbound_rx = state.inbound_rx.lock().await;

            loop {
                let (client, msg) = inbound_rx.recv().await.expect("todo");
                let data = format!("{:?} {:?}", client, msg);
                println!("{}", data);
                if let Err(_) = writer.write_all(data.as_bytes()).await {
                    break;
                }
            }
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

fn add_keepalives(stream: &tokio::net::TcpStream) -> Result<()> {
    use std::time::Duration;

    let sock_ref = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(60));
    sock_ref.set_tcp_keepalive(&ka)?;
    Ok(())
}
