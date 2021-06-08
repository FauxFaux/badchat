use std::collections::VecDeque;

use anyhow::Error;
use mio::tcp::TcpListener;

use super::Conn;
use super::ConnType;
use super::InputBuffer;
use super::NetConn;

pub struct PlainServer {
    server: TcpListener,
}

impl PlainServer {
    pub fn new(server: TcpListener) -> PlainServer {
        PlainServer { server }
    }

    pub fn accept(&mut self, poll: &mut mio::Poll, new_token: mio::Token) -> Result<Conn, Error> {
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
