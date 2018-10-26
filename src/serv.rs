use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net;
use std::sync::Arc;

use failure::Error;
use failure::ResultExt;
use mio::tcp::{Shutdown, TcpListener, TcpStream};
use rustls::NoClientAuth;
use rustls::Session;
use vecio::Rawv;

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

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

pub type Connections = HashMap<mio::Token, Connection>;

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    server: TcpListener,
    connections: Connections,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
}

impl TlsServer {
    fn new(server: TcpListener, cfg: Arc<rustls::ServerConfig>) -> TlsServer {
        TlsServer {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
        }
    }

    fn accept(&mut self, poll: &mut mio::Poll) -> Result<(), Error> {
        let (socket, addr) = self.server.accept()?;
        debug!("Accepting new connection from {:?}", addr);

        let tls_session = rustls::ServerSession::new(&self.tls_config);

        let token = mio::Token(self.next_id);
        self.next_id += 1;
        let conn = Connection::new(socket, token, tls_session);
        conn.register_on_connect(poll)?;
        self.connections.insert(token, conn);

        Ok(())
    }
}

pub struct Connection {
    socket: TcpStream,
    pub token: mio::Token,
    closing: bool,
    closed: bool,
    tls_session: rustls::ServerSession,
    pub input_buffer: VecDeque<u8>,
}

impl Connection {
    fn new(socket: TcpStream, token: mio::Token, tls_session: rustls::ServerSession) -> Connection {
        Connection {
            socket,
            token,
            closing: false,
            closed: false,
            tls_session,
            input_buffer: VecDeque::new(),
        }
    }

    /// We're a connection, and we have something to do.
    fn handle_readiness(&mut self, readiness: mio::Ready) -> Result<(), Error> {
        // If we're readable: read some TLS. Then see if that yielded new plaintext.
        if readiness.is_readable() {
            self.do_tls_read();
            self.try_plain_read()?;
        }

        if readiness.is_writable() {
            self.do_tls_write();
        }

        Ok(())
    }

    fn handle_registration(&mut self, poll: &mut mio::Poll) -> Result<(), Error> {
        if self.closing && !self.tls_session.wants_write() {
            let _ = self.socket.shutdown(Shutdown::Both);
            self.closed = true;
        } else {
            self.reregister(poll)?;
        }

        Ok(())
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        match self.tls_session.read_tls(&mut self.socket) {
            Ok(0) => {
                debug!("eof");
                self.closing = true;
            }

            Err(ref e) if io::ErrorKind::WouldBlock == e.kind() => (),

            Err(e) => {
                error!("read error {:?}", e);
                self.closing = true;
            }

            Ok(_) => {
                if let Err(e) = self.tls_session.process_new_packets() {
                    error!("cannot process packet: {:?}", e);
                    self.closing = true;
                }
            }
        }
    }

    fn try_plain_read(&mut self) -> Result<(), Error> {
        // Read and process all available plaintext.
        let mut buf = Vec::new();

        match self.tls_session.read_to_end(&mut buf) {
            Ok(0) => (),
            Ok(_) => {
                debug!("plaintext read {:?}", buf.len());
                self.input_buffer.extend(buf);
            }
            Err(e) => {
                error!("plaintext read failed: {:?}", e);
                self.closing = true;
            }
        }

        Ok(())
    }

    fn do_tls_write(&mut self) {
        let rc = self
            .tls_session
            .writev_tls(&mut WriteVAdapter::new(&mut self.socket));
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
            return;
        }
    }

    fn register_on_connect(&self, poll: &mut mio::Poll) -> Result<(), Error> {
        Ok(poll.register(
            &self.socket,
            self.token,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )?)
    }

    fn reregister(&self, poll: &mut mio::Poll) -> Result<(), Error> {
        Ok(poll.reregister(
            &self.socket,
            self.token,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )?)
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn start_closing(&mut self) {
        self.tls_session.send_close_notify();
        self.closing = true;
    }

    pub fn write_line(&mut self, val: &str) -> Result<(), Error> {
        self.tls_session.write_all(val.as_bytes())?;
        self.tls_session.write_all(b"\r\n")?;
        Ok(())
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

pub fn serve_forever<F: FnMut(&mut Connections)>(mut work: F) -> Result<(), Error> {
    let addr: net::SocketAddr = "127.0.0.1:6697".parse()?;

    let config = Arc::new(make_config()?);

    let listener =
        TcpListener::bind(&addr).with_context(|_| format_err!("cannot listen on port"))?;
    let mut poll = mio::Poll::new()?;
    poll.register(
        &listener,
        LISTENER,
        mio::Ready::readable(),
        mio::PollOpt::level(),
    )?;

    let mut tlsserv = TlsServer::new(listener, config);

    let mut events = mio::Events::with_capacity(256);
    loop {
        poll.poll(&mut events, None)?;

        // handle accepting and reading/writing data from/to active connections
        for event in events.iter() {
            match event.token() {
                LISTENER => tlsserv.accept(&mut poll)?,
                client => {
                    if let Some(conn) = tlsserv.connections.get_mut(&client) {
                        conn.handle_readiness(event.readiness())?;
                    }
                }
            }
        }

        // TODO: we don't need to do work, or re-register for all clients here,
        // TODO: but, by doing so, we make sure we don't miss anything.
        // TODO: is the performance relevant?

        // do useful application work on all clients
        work(&mut tlsserv.connections);

        // check if any of the work we did means there's more networking work to do
        for conn in tlsserv.connections.values_mut() {
            conn.handle_registration(&mut poll)?;
        }

        // check if anyone actually managed to die
        tlsserv.connections.retain(|_token, conn| !conn.is_closed());
    }
}
