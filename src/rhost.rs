use std::net::IpAddr;
use std::thread;
use std::time;
use std::sync::mpsc;

use dns_lookup;

#[derive(Debug)]
enum State {
    Waiting(mpsc::Receiver<Option<String>>),
    Done(Option<String>),
}

#[derive(Debug)]
pub struct ResolutionPending {
    ip: IpAddr,
    state: State,
}

pub fn reverse(ip: IpAddr) -> ResolutionPending {
    let (send, recv) = mpsc::sync_channel(1);
    thread::spawn(move || {
        send.send(dns_lookup::lookup_addr(&ip).ok())
    });

    ResolutionPending { state: State::Waiting(recv), ip }
}

impl ResolutionPending {
    pub fn done(&mut self) -> bool {
        match &self.state {
            State::Done(_) => true,
            State::Waiting(recv) => {
                match recv.try_recv() {
                    Ok(val) => {
                        self.state = State::Done(val);
                        true
                    },
                    Err(mpsc::TryRecvError::Disconnected) => {
                        State::Done(None);
                        true
                    },
                    Err(mpsc::TryRecvError::Empty) => false,
                }
            }
        }
    }

    pub fn get(mut self) -> String {
        self.done();

        let ip = self.ip;

        let result = match self.state {
            State::Done(val) => val,
            _ => None,
        };

        result.unwrap_or_else(|| ip.to_string())
    }
}
