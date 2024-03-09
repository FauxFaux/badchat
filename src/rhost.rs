use std::cell::RefCell;
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;

#[derive(Debug)]
enum State {
    Waiting(mpsc::Receiver<Option<String>>),
    Done(Option<String>),
}

#[derive(Debug)]
pub struct ResolutionPending {
    ip: IpAddr,
    state: RefCell<State>,
}

pub fn reverse(ip: IpAddr) -> ResolutionPending {
    let (send, recv) = mpsc::sync_channel(1);
    thread::spawn(move || send.send(dns_lookup::lookup_addr(&ip).ok()));

    ResolutionPending {
        state: RefCell::new(State::Waiting(recv)),
        ip,
    }
}

impl ResolutionPending {
    pub fn done(&self) -> bool {
        let new_val = match &*self.state.borrow() {
            State::Done(_) => return true,
            State::Waiting(recv) => match recv.try_recv() {
                Ok(val) => State::Done(val),
                Err(mpsc::TryRecvError::Disconnected) => State::Done(None),
                Err(mpsc::TryRecvError::Empty) => return false,
            },
        };

        self.state.replace(new_val);

        true
    }

    pub fn get(self) -> String {
        self.done();

        let ip = self.ip;

        let result = match self.state.into_inner() {
            State::Done(val) => val,
            State::Waiting(_) => None,
        };

        result
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| ip.to_string())
    }
}
