use std::io;
use std::io::Read;
use std::sync::Arc;

use anyhow::Error;
use mio::tcp::TcpListener;

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
        unimplemented!("accept");
    }
}

pub fn do_tls_read(net: &mut NetConn, tls_session: &mut ()) {
    unimplemented!()
}

/// @return true if some new data is available
pub fn try_plain_read(
    net: &mut NetConn,
    input: &mut InputBuffer,
    tls_session: &mut (),
) -> Result<bool, Error> {
    unimplemented!()
}

pub fn do_tls_write(net: &mut NetConn, tls_session: &mut ()) {
    unimplemented!()
}
