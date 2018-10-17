#[macro_use]
extern crate crossbeam_channel;
#[macro_use]
extern crate failure;

use std::net;
use std::io;
use std::io::BufRead;
use std::io::Write;
use std::thread;

use failure::Error;
use crossbeam_channel as channel;

fn main() -> Result<(), Error> {
    let serv = net::TcpListener::bind("127.0.0.1:3730")?;

    let (s, r) = channel::unbounded();

    for client in serv.incoming() {
        let mut client = client?;
        let mut read = io::BufReader::new(&client);
        let s = s.clone();
        thread::spawn(move || {
            loop {
                let mut str = String::new();
                read.read_line(&mut str).unwrap();
                s.send(str);
            }
        });

        thread::spawn(move || {
            while let Some(msg) = r.recv() {
               write!(client, "{}", msg);
            }
        });
    }
    Ok(())
}
