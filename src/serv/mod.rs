use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::io::Read;
use std::io::Write;
use std::net;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context as _;
use anyhow::Error;
use mio::tcp::Shutdown;
use mio::tcp::TcpListener;
use mio::tcp::TcpStream;
use mio::Token;
use rustls::ServerConfig;

mod plain;
mod tls;
mod tls_config;

use crate::rhost;

pub use self::tls_config::make_default_tls_config;

pub type Connections = HashMap<mio::Token, Conn>;

enum Server {
    Plain(plain::PlainServer),
    Tls(tls::TlsServer),
}

impl Server {
    fn accept(&mut self, poll: &mut mio::Poll, new_token: mio::Token) -> Result<Conn, Error> {
        match self {
            Server::Plain(server) => server.accept(poll, new_token),
            Server::Tls(server) => server.accept(poll, new_token),
        }
    }
}

pub enum ConnType {
    Plain(VecDeque<u8>),
}

pub struct NetConn {
    socket: TcpStream,
    pub token: mio::Token,
    closing: bool,
    closed: bool,
}

#[derive(Clone, Default)]
pub struct InputBuffer {
    pub buf: VecDeque<u8>,

    /// The client angered us. We are discarding until they send us a line break.
    pub broken: bool,
}

pub struct Conn {
    pub net: NetConn,
    pub input: InputBuffer,
    extra: ConnType,
}

impl Conn {
    /// We're a connection, and we have something to do.
    /// @return true if we generated some new input to process
    fn handle_readiness(&mut self, readiness: mio::Ready) -> Result<bool, Error> {
        let mut new_input = false;

        match &mut self.extra {
            ConnType::Plain(output) => {
                if readiness.is_readable() {
                    let mut buf = [0u8; 4096];

                    // TODO: if the wakeup was a lie, presumably this can return WouldBlock
                    let read = self
                        .net
                        .socket
                        .read(&mut buf)
                        .with_context(|| anyhow!("reading"))?;
                    if 0 == read {
                        // EOF!
                        self.net.closing = true;
                    } else {
                        new_input = true;
                        self.input.buf.extend(&buf[..read]);
                    }
                }

                if readiness.is_writable() {
                    let (first, then) = output.as_slices();
                    // TODO: presumably this can at least theoretically block
                    self.net
                        .socket
                        .write_all(first)
                        .with_context(|| anyhow!("writing first"))?;
                    self.net
                        .socket
                        .write_all(then)
                        .with_context(|| anyhow!("writing then"))?;
                    output.clear();
                }
            }
        }
        Ok(new_input)
    }

    pub fn handle_registration(&mut self, poll: &mut mio::Poll) -> Result<(), Error> {
        if self.net.closing
            && match &mut self.extra {
                ConnType::Plain(output) => output.is_empty(),
            }
        {
            let _ = self.net.socket.shutdown(Shutdown::Both);
            self.net.closed = true;
            return Ok(());
        }

        poll.reregister(
            &self.net.socket,
            self.net.token,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )?;
        Ok(())
    }

    pub fn write_line<S: AsRef<str>>(&mut self, val: S) -> Result<(), Error> {
        let val = val.as_ref();
        trace!("output: {:?}: {:?})", self.net.token, val);
        match &mut self.extra {
            ConnType::Plain(output) => {
                output.extend(val.as_bytes());
                output.extend(b"\r\n");
            }
        }
        Ok(())
    }

    pub fn start_closing(&mut self) {
        if !self.net.closing {
            self.net.closing = true;
        }
    }

    pub fn event_set(&self) -> mio::Ready {
        let (rd, wr) = match &self.extra {
            ConnType::Plain(output) => (true, !output.is_empty()),
        };

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    pub fn reverse(&self) -> rhost::ResolutionPending {
        rhost::reverse(
            self.net
                .socket
                .peer_addr()
                .expect("socket must have a remote address?")
                .ip(),
        )
    }
}

pub struct Context {
    poll: mio::Poll,
    next_id: usize,
    servers: HashMap<mio::Token, Server>,
    connections: Connections,
    events: mio::Events,
}

impl Context {
    pub fn new() -> Result<Context, Error> {
        Ok(Context {
            poll: mio::Poll::new()?,
            next_id: 1,
            servers: HashMap::with_capacity(4),
            connections: HashMap::with_capacity(128),
            events: mio::Events::with_capacity(256),
        })
    }

    pub fn bind_plain(&mut self, addr: net::SocketAddr) -> Result<(), Error> {
        let (token, server) = self.bind(addr)?;
        self.servers
            .insert(token, Server::Plain(plain::PlainServer::new(server)));
        Ok(())
    }

    pub fn bind_tls(
        &mut self,
        addr: net::SocketAddr,
        tls_config: Arc<ServerConfig>,
    ) -> Result<(), Error> {
        let (token, server) = self.bind(addr)?;
        self.servers
            .insert(token, Server::Tls(tls::TlsServer::new(server, tls_config)));
        Ok(())
    }

    pub fn drive<F: FnMut(&HashSet<Token>, &mut Connections)>(
        &mut self,
        mut work: F,
    ) -> Result<(), Error> {
        self.poll.poll(&mut self.events, None)?;

        let mut useful_tokens = HashSet::with_capacity(4);

        // handle accepting and reading/writing data from/to active connections
        for event in self.events.iter() {
            let token = event.token();
            if let Some(server) = self.servers.get_mut(&token) {
                let token = mio::Token(self.next_id);
                self.next_id += 1;
                self.connections
                    .insert(token, server.accept(&mut self.poll, token)?);
            } else if let Some(conn) = self.connections.get_mut(&token) {
                if conn.handle_readiness(event.readiness())? {
                    useful_tokens.insert(token);
                }
            } else {
                error!("saw a token that wasn't tracked: {:?}", token)
            }
        }

        // do useful application work on clients
        work(&useful_tokens, &mut self.connections);

        // check if any of the work we did means there's more networking work to do
        for conn in self.connections.values_mut() {
            conn.handle_registration(&mut self.poll)?;
        }

        // check if anyone actually managed to die
        self.connections.retain(|_token, conn| !conn.net.closed);

        Ok(())
    }

    fn bind(&mut self, addr: net::SocketAddr) -> Result<(mio::Token, TcpListener), Error> {
        let token = mio::Token(self.next_id);
        self.next_id += 1;

        let listener =
            TcpListener::bind(&addr).with_context(|| format_err!("cannot listen on {:?}", addr))?;

        self.poll.register(
            &listener,
            token,
            mio::Ready::readable(),
            mio::PollOpt::level(),
        )?;

        info!(
            "{:?} is bound to {:?} ({:?})",
            token,
            addr,
            listener.local_addr()?,
        );

        Ok((token, listener))
    }
}
