use std::io;
use std::io::Read;
use std::sync::Arc;

use anyhow::Error;
use mio::tcp::TcpListener;
use rustls::Session;

use crate::serv::Conn;
use crate::serv::ConnType;
use crate::serv::InputBuffer;
use crate::serv::NetConn;

pub struct TlsServer {
    server: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
}

impl TlsServer {
    pub fn new(server: TcpListener, tls_config: Arc<rustls::ServerConfig>) -> TlsServer {
        TlsServer { server, tls_config }
    }

    pub fn accept(&mut self, poll: &mut mio::Poll, new_token: mio::Token) -> Result<Conn, Error> {
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

pub fn do_tls_read(net: &mut NetConn, tls_session: &mut rustls::ServerSession) {
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
pub fn try_plain_read(
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

pub fn do_tls_write(net: &mut NetConn, tls_session: &mut rustls::ServerSession) {
    let rc = tls_session.write_tls(&mut net.socket);
    if rc.is_err() {
        error!("write failed {:?}", rc);
        net.closing = true;
        return;
    }
}
