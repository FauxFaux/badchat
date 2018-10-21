extern crate env_logger;
#[macro_use]
extern crate failure;
extern crate irc;
#[macro_use]
extern crate log;
extern crate mio;
extern crate rustls;
extern crate vecio;

mod serv;

use std::collections::HashMap;
use std::collections::VecDeque;

use failure::Error;
use failure::ResultExt;

type ConnId = mio::Token;

#[derive(Default)]
struct System {
    registering: HashMap<ConnId, ()>,
    clients: HashMap<ConnId, Client>,
}

struct PreAuth {
    nick: Option<String>,
    pass: Option<String>,
    gecos: Option<(String, String)>,
}

struct Client {
    nick: String,
}

#[derive(Copy, Clone, Debug)]
enum ErrorCode {
    BadCharEncoding,
}

impl ErrorCode {
    fn to_numeric(&self) -> u16 {
        match self {
            ErrorCode::BadCharEncoding => 980,
        }
    }
}

impl System {
    fn new() -> System {
        System::default()
    }

    fn work(&mut self, connections: &mut serv::Connections) {
        for (_token, connection) in connections {
            if let Err(e) = self.process_commands(connection) {
                error!("failed processing commands: {:?}", e);
                connection.start_closing();
            }
        }
    }

    fn process_commands(&mut self, conn: &mut serv::Connection) -> Result<(), Error> {
        while let Some(line) = pop_line(&mut conn.input_buffer) {
            let line = match String::from_utf8(line) {
                Ok(line) => line,
                Err(_) => {
                    conn.write_line(&format!(
                        ":ircd {} * :utf-8 only please",
                        ErrorCode::BadCharEncoding.to_numeric()
                    ))?;
                    continue;
                }
            };

            let message: irc::proto::Message = line.parse()?;
            println!("{:?}", message);
        }

        Ok(())
    }
}

fn pop_line(buf: &mut VecDeque<u8>) -> Option<Vec<u8>> {
    if let Some(pos) = buf.iter().position(|&b| b'\n' == b) {
        let mut vec: Vec<u8> = buf.drain(..pos).collect();
        assert_eq!(Some(b'\n'), buf.pop_front());
        while vec.ends_with(&[b'\r']) {
            vec.pop();
        }
        Some(vec)
    } else {
        None
    }
}

fn main() -> Result<(), Error> {
    env_logger::Builder::new().parse("trace").init();

    let mut system = System::new();

    Ok(serv::serve_forever(|connections| system.work(connections))
        .with_context(|_| format_err!("running server"))?)
}
