#[macro_use]
extern crate failure;

use std::io;
use std::io::BufRead;
use std::io::Write;
use std::net;
use std::sync;
use std::thread;

use failure::Error;

fn main() -> Result<(), Error> {
    let serv = net::TcpListener::bind("127.0.0.1:3730")?;

    let live_clients = sync::Arc::new(sync::Mutex::new(Vec::new()));

    for client in serv.incoming() {
        let client = client?;
        let mut client = io::BufReader::new(client);
        let (s, r) = sync::mpsc::channel();
        live_clients.lock().unwrap().push(s);
        let live_clients = live_clients.clone();
        thread::spawn(move || loop {
            let mut buf = String::new();
            client.read_line(&mut buf).unwrap();
            let buf = buf.trim().to_string();
            for client in live_clients.lock().unwrap().iter() {
                client.send(buf.to_string()).unwrap();
            }

            while let Ok(msg) = r.try_recv() {
                writeln!(client.get_mut(), "{}", msg).unwrap();
            }
        });
    }
    Ok(())
}
