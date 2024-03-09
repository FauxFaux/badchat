mod admin;
mod tempura;
mod worker;

use std::collections::HashMap;
use std::io::{self};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{MessageIn, MessageOut, Uid};
use admin::run_admin;
use anyhow::{anyhow, bail, Context, Result};
use bunyarrs::{vars, vars_dbg, Bunyarr};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tempura::{add_keepalives, load_certs, load_keys};
use tokio::net::TcpListener;
use tokio::select;
use tokio::signal::unix::SignalKind;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use worker::run_worker;

#[derive(serde::Deserialize, Clone)]
struct Options {
    cert: PathBuf,
    key: PathBuf,
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

pub async fn main() -> Result<()> {
    let logger = Bunyarr::with_name("main");

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
            let stream = match timeout(Duration::from_secs(2), acceptor.accept(stream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => {
                    state
                        .logger
                        .info(vars_dbg! { addr, err }, "tls accept failed");
                    return;
                }
                Err(_timeout_elapsed) => {
                    state.logger.info(vars! { addr }, "tls accept timed out");
                    return;
                }
            };
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
