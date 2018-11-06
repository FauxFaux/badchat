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

pub type Connections = HashMap<mio::Token, Conn>;

struct PlainServer {
    server: TcpListener,
}

struct TlsServer {
    server: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
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
            extra: ConnType::Plain,
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

        let mut tls_session = rustls::ServerSession::new(&self.tls_config);

        let mut net = NetConn {
            socket,
            token: new_token,
            closing: false,
            closed: false,
        };

        register_on_connect(&mut net, poll, event_set(&mut tls_session))?;

        let conn = Conn {
            net,
            input: InputBuffer::default(),
            extra: ConnType::Tls(tls_session),
        };

        Ok(conn)
    }
}

pub enum ConnType {
    Plain,
    Tls(rustls::ServerSession),
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

pub struct Conn {
    net: NetConn,
    input: InputBuffer,
    extra: ConnType,
}

impl Conn {
    fn handle_readiness(&mut self, readiness: mio::Ready) -> Result<bool, Error> {
        match &mut self.extra {
            ConnType::Tls(tls) => handle_readiness(&mut self.net, &mut self.input, tls, readiness),
            ConnType::Plain => unimplemented!("plain conn is ready"),
        }
    }

    pub fn handle_registration(&mut self, poll: &mut mio::Poll) -> Result<(), Error> {
        match &mut self.extra {
            ConnType::Tls(tls) => handle_registration(&mut self.net, poll, tls),
            ConnType::Plain => unimplemented!("plain conn handle registration"),
        }
    }

    pub fn write_line<S: AsRef<str>>(&mut self, val: S) -> Result<(), Error> {
        match &mut self.extra {
            ConnType::Plain => unimplemented!("plain conn write_line"),
            ConnType::Tls(tls) => write_line(&mut self.net, tls, val),
        }
    }

    pub fn start_closing(&mut self) {
        if !self.net.closing {
            if let ConnType::Tls(tls) = &mut self.extra {
                tls.send_close_notify();
            }
            self.net.closing = true;
        }
    }

    pub fn is_closed(&self) -> bool {
        self.net.closed
    }

    pub fn broken_input(&mut self) -> bool {
        self.input.broken
    }

    pub fn break_input(&mut self, to: bool) {
        self.input.broken = to;
    }

    pub fn input_buffer(&mut self) -> &mut VecDeque<u8> {
        &mut self.input.buf
    }

    pub fn token(&mut self) -> mio::Token {
        self.net.token
    }
}

/// We're a connection, and we have something to do.
/// @return true if we generated some new input to process
fn handle_readiness(
    net: &mut NetConn,
    input: &mut InputBuffer,
    tls_session: &mut rustls::ServerSession,
    readiness: mio::Ready,
) -> Result<bool, Error> {
    // If we're readable: read some TLS. Then see if that yielded new plaintext.
    let mut new_input = false;

    if readiness.is_readable() {
        do_tls_read(net, tls_session);
        new_input |= try_plain_read(net, input, tls_session)?;
    }

    if readiness.is_writable() {
        do_tls_write(net, tls_session);
    }

    Ok(new_input)
}

fn handle_registration(
    net: &mut NetConn,
    poll: &mut mio::Poll,
    tls_session: &mut rustls::ServerSession,
) -> Result<(), Error> {
    if net.closing && !tls_session.wants_write() {
        let _ = net.socket.shutdown(Shutdown::Both);
        net.closed = true;
    } else {
        reregister(net, poll, event_set(tls_session))?;
    }

    Ok(())
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

fn register_on_connect(
    net: &mut NetConn,
    poll: &mut mio::Poll,
    interest: mio::Ready,
) -> Result<(), Error> {
    Ok(poll.register(
        &net.socket,
        net.token,
        interest,
        mio::PollOpt::level() | mio::PollOpt::oneshot(),
    )?)
}

fn reregister(net: &mut NetConn, poll: &mut mio::Poll, interest: mio::Ready) -> Result<(), Error> {
    Ok(poll.reregister(
        &net.socket,
        net.token,
        interest,
        mio::PollOpt::level() | mio::PollOpt::oneshot(),
    )?)
}

/// What IO events we're currently waiting for,
/// based on wants_read/wants_write.
fn event_set(tls_session: &mut rustls::ServerSession) -> mio::Ready {
    let rd = tls_session.wants_read();
    let wr = tls_session.wants_write();

    if rd && wr {
        mio::Ready::readable() | mio::Ready::writable()
    } else if wr {
        mio::Ready::writable()
    } else {
        mio::Ready::readable()
    }
}

pub fn write_line<S: AsRef<str>>(
    net: &mut NetConn,
    tls_session: &mut rustls::ServerSession,
    val: S,
) -> Result<(), Error> {
    let val = val.as_ref();
    trace!("output: {:?}: {:?})", net.token, val);
    tls_session.write_all(val.as_bytes())?;
    tls_session.write_all(b"\r\n")?;
    Ok(())
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
                    connections.insert(token, plain.accept(&mut poll, token)?);
                }
                TLS_LISTENER => {
                    last_id += 1;
                    let token = mio::Token(last_id);
                    connections.insert(token, tlsserv.accept(&mut poll, token)?);
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
