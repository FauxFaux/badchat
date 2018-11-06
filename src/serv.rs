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

use failure::Error;
use failure::ResultExt;
use mio::tcp::Shutdown;
use mio::tcp::TcpListener;
use mio::tcp::TcpStream;
use mio::Token;
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

const PLAIN_LISTENER: mio::Token = mio::Token(1);
const TLS_LISTENER: mio::Token = mio::Token(2);

pub type Connections = HashMap<mio::Token, ConnType>;

struct PlainServer {
    server: TcpListener,
}

struct TlsServer {
    server: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
}

impl PlainServer {
    fn accept(&mut self, poll: &mut mio::Poll, new_token: mio::Token) -> Result<PlainConn, Error> {
        let (socket, addr) = self.server.accept()?;
        debug!("Accepting new plain connection from {:?}", addr);

        let conn = PlainConn {
            net: NetConn {
                socket,
                token: new_token,
                closing: false,
                closed: false,
            },
            input: InputBuffer::default(),
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

    fn accept(&mut self, poll: &mut mio::Poll, new_token: mio::Token) -> Result<TlsConn, Error> {
        let (socket, addr) = self.server.accept()?;
        debug!("Accepting new tls connection from {:?}", addr);

        let tls_session = rustls::ServerSession::new(&self.tls_config);

        let conn = TlsConn::new(socket, new_token, tls_session);
        conn.register_on_connect(poll)?;

        Ok(conn)
    }
}

pub enum ConnType {
    Plain(PlainConn),
    Tls(TlsConn),
}

pub struct NetConn {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
}

#[derive(Clone, Default)]
pub struct InputBuffer {
    buf: VecDeque<u8>,

    /// The client angered us. We are discarding until they send us a line break.
    broken: bool,
}

pub struct PlainConn {
    net: NetConn,
    input: InputBuffer,
}

pub struct TlsConn {
    net: NetConn,
    input: InputBuffer,

    tls_session: rustls::ServerSession,
}

impl ConnType {
    fn net(&mut self) -> &mut NetConn {
        match self {
            ConnType::Plain(plain) => &mut plain.net,
            ConnType::Tls(tls) => &mut tls.net,
        }
    }

    fn input(&mut self) -> &mut InputBuffer {
        match self {
            ConnType::Plain(plain) => &mut plain.input,
            ConnType::Tls(tls) => &mut tls.input,
        }
    }
    fn handle_readiness(&mut self, readiness: mio::Ready) -> Result<bool, Error> {
        match self {
            ConnType::Tls(tls) => tls.handle_readiness(readiness),
            ConnType::Plain(_) => unimplemented!("plain conn is ready"),
        }
    }

    pub fn handle_registration(&mut self, poll: &mut mio::Poll) -> Result<(), Error> {
        match self {
            ConnType::Tls(tls) => tls.handle_registration(poll),
            ConnType::Plain(_) => unimplemented!("plain conn handle registration"),
        }
    }

    pub fn write_line<S: AsRef<str>>(&mut self, val: S) -> Result<(), Error> {
        match self {
            ConnType::Plain(_) => unimplemented!("plain conn write_line"),
            ConnType::Tls(tls) => tls.write_line(val),
        }
    }

    pub fn start_closing(&mut self) {
        self.net().closing = true;
    }

    pub fn is_closed(&mut self) -> bool {
        self.net().closed
    }

    pub fn broken_input(&mut self) -> bool {
        self.input().broken
    }

    pub fn break_input(&mut self, to: bool) {
        self.input().broken = to;
    }

    pub fn input_buffer(&mut self) -> &mut VecDeque<u8> {
        &mut self.input().buf
    }

    pub fn token(&mut self) -> mio::Token {
        self.net().token
    }
}

impl TlsConn {
    fn new(socket: TcpStream, token: mio::Token, tls_session: rustls::ServerSession) -> TlsConn {
        TlsConn {
            net: NetConn {
                socket,
                token,
                closing: false,
                closed: false,
            },
            tls_session,
            input: InputBuffer::default(),
        }
    }

    /// We're a connection, and we have something to do.
    /// @return true if we generated some new input to process
    fn handle_readiness(&mut self, readiness: mio::Ready) -> Result<bool, Error> {
        // If we're readable: read some TLS. Then see if that yielded new plaintext.
        let mut new_input = false;

        if readiness.is_readable() {
            self.do_tls_read();
            new_input |= self.try_plain_read()?;
        }

        if readiness.is_writable() {
            self.do_tls_write();
        }

        Ok(new_input)
    }

    fn handle_registration(&mut self, poll: &mut mio::Poll) -> Result<(), Error> {
        if self.net.closing && !self.tls_session.wants_write() {
            let _ = self.net.socket.shutdown(Shutdown::Both);
            self.net.closed = true;
        } else {
            self.reregister(poll)?;
        }

        Ok(())
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        match self.tls_session.read_tls(&mut self.net.socket) {
            Ok(0) => {
                debug!("eof");
                self.net.closing = true;
            }

            Err(ref e) if io::ErrorKind::WouldBlock == e.kind() => (),

            Err(e) => {
                error!("read error {:?}", e);
                self.net.closing = true;
            }

            Ok(_) => {
                if let Err(e) = self.tls_session.process_new_packets() {
                    error!("cannot process packet: {:?}", e);
                    self.net.closing = true;
                }
            }
        }
    }

    /// @return true if some new data is available
    fn try_plain_read(&mut self) -> Result<bool, Error> {
        // Read and process all available plaintext.
        let mut buf = Vec::new();

        Ok(match self.tls_session.read_to_end(&mut buf) {
            Ok(0) => false,
            Ok(_) => {
                debug!("plaintext read {:?}", buf.len());
                self.input.buf.extend(buf);
                true
            }
            Err(e) => {
                error!("plaintext read failed: {:?}", e);
                self.net.closing = true;
                false
            }
        })
    }

    fn do_tls_write(&mut self) {
        let rc = self
            .tls_session
            .writev_tls(&mut WriteVAdapter::new(&mut self.net.socket));
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.net.closing = true;
            return;
        }
    }

    fn register_on_connect(&self, poll: &mut mio::Poll) -> Result<(), Error> {
        Ok(poll.register(
            &self.net.socket,
            self.net.token,
            self.event_set(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )?)
    }

    fn reregister(&self, poll: &mut mio::Poll) -> Result<(), Error> {
        Ok(poll.reregister(
            &self.net.socket,
            self.net.token,
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
        self.net.closed
    }

    pub fn start_closing(&mut self) {
        if !self.net.closing {
            self.tls_session.send_close_notify();
            self.net.closing = true;
        }
    }

    pub fn write_line<S: AsRef<str>>(&mut self, val: S) -> Result<(), Error> {
        let val = val.as_ref();
        trace!("output: {:?}: {:?})", self.net.token, val);
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

pub fn serve_forever<F: FnMut(&HashSet<Token>, &mut Connections)>(
    mut work: F,
) -> Result<(), Error> {
    let mut poll = mio::Poll::new()?;

    let mut plain = bind_plain(&mut poll)?;
    let mut tlsserv = bind_tls(&mut poll)?;

    let mut connections = HashMap::with_capacity(32);

    let mut last_id: usize = 3;

    let mut events = mio::Events::with_capacity(256);
    loop {
        poll.poll(&mut events, None)?;

        let mut useful_tokens = HashSet::with_capacity(4);

        // handle accepting and reading/writing data from/to active connections
        for event in events.iter() {
            match event.token() {
                PLAIN_LISTENER => {
                    last_id += 1;
                    let token = mio::Token(last_id);
                    connections.insert(token, ConnType::Plain(plain.accept(&mut poll, token)?));
                }
                TLS_LISTENER => {
                    last_id += 1;
                    let token = mio::Token(last_id);
                    connections.insert(token, ConnType::Tls(tlsserv.accept(&mut poll, token)?));
                }
                client => {
                    if let Some(conn) = connections.get_mut(&client) {
                        if conn.handle_readiness(event.readiness())? {
                            useful_tokens.insert(client);
                        }
                    }
                }
            }
        }

        // do useful application work on clients
        work(&useful_tokens, &mut connections);

        // check if any of the work we did means there's more networking work to do
        for conn in connections.values_mut() {
            conn.handle_registration(&mut poll)?;
        }

        // check if anyone actually managed to die
        connections.retain(|_token, conn| !conn.is_closed());
    }
}

fn bind_plain(poll: &mut mio::Poll) -> Result<PlainServer, Error> {
    let addr: net::SocketAddr = "0.0.0.0:6667".parse()?;
    let listener =
        TcpListener::bind(&addr).with_context(|_| format_err!("cannot listen on tls port"))?;

    poll.register(
        &listener,
        PLAIN_LISTENER,
        mio::Ready::readable(),
        mio::PollOpt::level(),
    )?;

    Ok(PlainServer { server: listener })
}

fn bind_tls(poll: &mut mio::Poll) -> Result<TlsServer, Error> {
    let addr: net::SocketAddr = "0.0.0.0:6697".parse()?;

    let config = Arc::new(make_config()?);

    let listener =
        TcpListener::bind(&addr).with_context(|_| format_err!("cannot listen on tls port"))?;

    poll.register(
        &listener,
        TLS_LISTENER,
        mio::Ready::readable(),
        mio::PollOpt::level(),
    )?;

    Ok(TlsServer::new(listener, config))
}
