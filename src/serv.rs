use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net;
use std::sync::Arc;

use failure::err_msg;
use failure::Error;
use failure::ResultExt;
use mio::tcp::Shutdown;
use mio::tcp::TcpListener;
use mio::tcp::TcpStream;
use mio::Token;
use rustls::NoClientAuth;
use rustls::Session;
use vecio::Rawv;

use crate::rhost;

/// This glues our `rustls::WriteV` trait to `vecio::Rawv`.
pub struct WriteVAdapter<'a> {
    rawv: &'a mut Rawv,
}

impl<'a> WriteVAdapter<'a> {
    pub fn new(rawv: &'a mut Rawv) -> WriteVAdapter<'a> {
        WriteVAdapter { rawv }
    }
}

impl<'a> rustls::WriteV for WriteVAdapter<'a> {
    fn writev(&mut self, bytes: &[&[u8]]) -> io::Result<usize> {
        self.rawv.writev(bytes)
    }
}

pub type Connections = HashMap<mio::Token, Conn>;

enum Server {
    Plain(PlainServer),
    Tls(TlsServer),
}

struct PlainServer {
    server: TcpListener,
}

struct TlsServer {
    server: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
}

impl Server {
    fn accept(&mut self, poll: &mut mio::Poll, new_token: mio::Token) -> Result<Conn, Error> {
        match self {
            Server::Plain(server) => server.accept(poll, new_token),
            Server::Tls(server) => server.accept(poll, new_token),
        }
    }
}

impl PlainServer {
    fn accept(&mut self, poll: &mut mio::Poll, new_token: mio::Token) -> Result<Conn, Error> {
        let (socket, addr) = self.server.accept()?;
        debug!("Accepting new plain connection from {:?}", addr);

        let conn = Conn {
            net: NetConn {
                socket,
                token: new_token,
                closing: false,
                closed: false,
            },
            input: InputBuffer::default(),
            extra: ConnType::Plain(VecDeque::new()),
        };

        poll.register(
            &conn.net.socket,
            new_token,
            mio::Ready::readable() | mio::Ready::writable(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )?;

        Ok(conn)
    }
}

impl TlsServer {
    fn new(server: TcpListener, cfg: Arc<rustls::ServerConfig>) -> TlsServer {
        TlsServer {
            server,
            tls_config: cfg,
        }
    }

    fn accept(&mut self, poll: &mut mio::Poll, new_token: mio::Token) -> Result<Conn, Error> {
        let (socket, addr) = self.server.accept()?;
        debug!("Accepting new tls connection from {:?}", addr);

        let tls_session = rustls::ServerSession::new(&self.tls_config);

        let net = NetConn {
            socket,
            token: new_token,
            closing: false,
            closed: false,
        };

        poll.register(
            &net.socket,
            net.token,
            mio::Ready::readable() | mio::Ready::writable(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )?;

        let conn = Conn {
            net,
            input: InputBuffer::default(),
            extra: ConnType::Tls(tls_session),
        };

        Ok(conn)
    }
}

pub enum ConnType {
    Plain(VecDeque<u8>),
    Tls(rustls::ServerSession),
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
                        .with_context(|_| err_msg("reading"))?;
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
                        .with_context(|_| err_msg("writing first"))?;
                    self.net
                        .socket
                        .write_all(then)
                        .with_context(|_| err_msg("writing then"))?;
                    output.clear();
                }
            }
            ConnType::Tls(tls) => {
                // If we're readable: read some TLS. Then see if that yielded new plaintext.

                if readiness.is_readable() {
                    do_tls_read(&mut self.net, tls);
                    new_input |= try_plain_read(&mut self.net, &mut self.input, tls)?;
                }

                if readiness.is_writable() {
                    do_tls_write(&mut self.net, tls);
                }
            }
        }
        Ok(new_input)
    }

    pub fn handle_registration(&mut self, poll: &mut mio::Poll) -> Result<(), Error> {
        if self.net.closing
            && match &mut self.extra {
                ConnType::Plain(output) => output.is_empty(),
                ConnType::Tls(tls) => !tls.wants_write(),
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
            ConnType::Tls(tls) => {
                tls.write_all(val.as_bytes())?;
                tls.write_all(b"\r\n")?;
            }
        }
        Ok(())
    }

    pub fn start_closing(&mut self) {
        if !self.net.closing {
            if let ConnType::Tls(tls) = &mut self.extra {
                tls.send_close_notify();
            }
            self.net.closing = true;
        }
    }

    pub fn event_set(&self) -> mio::Ready {
        let (rd, wr) = match &self.extra {
            ConnType::Plain(output) => (true, !output.is_empty()),
            ConnType::Tls(tls) => (tls.wants_read(), tls.wants_write()),
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

fn do_tls_read(net: &mut NetConn, tls_session: &mut rustls::ServerSession) {
    // Read some TLS data.
    match tls_session.read_tls(&mut net.socket) {
        Ok(0) => {
            debug!("eof");
            net.closing = true;
        }

        Err(ref e) if io::ErrorKind::WouldBlock == e.kind() => (),

        Err(e) => {
            error!("read error {:?}", e);
            net.closing = true;
        }

        Ok(_) => {
            if let Err(e) = tls_session.process_new_packets() {
                error!("cannot process packet: {:?}", e);
                net.closing = true;
            }
        }
    }
}

/// @return true if some new data is available
fn try_plain_read(
    net: &mut NetConn,
    input: &mut InputBuffer,
    tls_session: &mut rustls::ServerSession,
) -> Result<bool, Error> {
    // Read and process all available plaintext.
    let mut buf = Vec::new();

    Ok(match tls_session.read_to_end(&mut buf) {
        Ok(0) => false,
        Ok(_) => {
            debug!("plaintext read {:?}", buf.len());
            input.buf.extend(buf);
            true
        }
        Err(e) => {
            error!("plaintext read failed: {:?}", e);
            net.closing = true;
            false
        }
    })
}

fn do_tls_write(net: &mut NetConn, tls_session: &mut rustls::ServerSession) {
    let rc = tls_session.writev_tls(&mut WriteVAdapter::new(&mut net.socket));
    if rc.is_err() {
        error!("write failed {:?}", rc);
        net.closing = true;
        return;
    }
}

fn load_certs(filename: &str) -> Result<Vec<rustls::Certificate>, Error> {
    let certfile =
        fs::File::open(filename).with_context(|_| format_err!("cannot open certificate file"))?;
    let mut reader = BufReader::new(certfile);
    Ok(rustls::internal::pemfile::certs(&mut reader)
        .map_err(|()| format_err!("pemfile certs reader"))?)
}

fn load_private_key(filename: &str) -> Result<rustls::PrivateKey, Error> {
    let rsa_keys = {
        let keyfile = fs::File::open(filename)
            .with_context(|_| format_err!("cannot open private key file"))?;
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .map_err(|()| format_err!("file contains invalid rsa private key"))?
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename)
            .with_context(|_| format_err!("cannot open private key file"))?;
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader).map_err(|_| {
            format_err!("file contains invalid pkcs8 private key (encrypted keys not supported)")
        })?
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        Ok(pkcs8_keys[0].clone())
    } else {
        assert!(!rsa_keys.is_empty());
        Ok(rsa_keys[0].clone())
    }
}

fn make_config() -> Result<rustls::ServerConfig, Error> {
    let mut config = rustls::ServerConfig::new(NoClientAuth::new());
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let certs = load_certs("localhost.crt")?;
    let privkey = load_private_key("localhost.key")?;
    config
        .set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .with_context(|_| format_err!("bad certificates/private key"))?;

    Ok(config)
}

pub fn serve_forever<F: FnMut(&HashSet<Token>, &mut Connections)>(
    mut work: F,
) -> Result<(), Error> {
    let mut poll = mio::Poll::new()?;
    let mut last_id: usize = 1;

    let mut servers = HashMap::with_capacity(4);

    let tls_config = Arc::new(make_config()?);

    for (addr, ssl) in &[("[::]:6667", false), ("[::]:6697", true)] {
        let token = mio::Token(last_id);
        last_id += 1;

        let addr = addr.parse()?;
        let server = bind(&mut poll, addr, token)?;

        let server = if *ssl {
            Server::Tls(TlsServer::new(server, tls_config.clone()))
        } else {
            Server::Plain(PlainServer { server })
        };

        trace!(
            "{:?} is a {} server on {:?}",
            token,
            if *ssl { "ssl" } else { "plain" },
            addr
        );

        servers.insert(token, server);
    }

    let mut connections = HashMap::with_capacity(32);

    let mut events = mio::Events::with_capacity(256);
    loop {
        poll.poll(&mut events, None)?;

        let mut useful_tokens = HashSet::with_capacity(4);

        // handle accepting and reading/writing data from/to active connections
        for event in events.iter() {
            let token = event.token();
            if let Some(server) = servers.get_mut(&token) {
                last_id += 1;
                let token = mio::Token(last_id);
                connections.insert(token, server.accept(&mut poll, token)?);
            } else if let Some(conn) = connections.get_mut(&token) {
                if conn.handle_readiness(event.readiness())? {
                    useful_tokens.insert(token);
                }
            } else {
                error!("saw a token that wasn't tracked: {:?}", token)
            }
        }

        // do useful application work on clients
        work(&useful_tokens, &mut connections);

        // check if any of the work we did means there's more networking work to do
        for conn in connections.values_mut() {
            conn.handle_registration(&mut poll)?;
        }

        // check if anyone actually managed to die
        connections.retain(|_token, conn| !conn.net.closed);
    }
}

fn bind(
    poll: &mut mio::Poll,
    addr: net::SocketAddr,
    token: mio::Token,
) -> Result<TcpListener, Error> {
    let listener =
        TcpListener::bind(&addr).with_context(|_| format_err!("cannot listen on tls port"))?;

    poll.register(
        &listener,
        token,
        mio::Ready::readable(),
        mio::PollOpt::level(),
    )?;

    Ok(listener)
}
