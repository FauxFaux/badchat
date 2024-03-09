use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::io::{split, AsyncBufReadExt, AsyncRead, AsyncWrite};

use crate::State;

pub fn run_admin<RW: AsyncRead + AsyncWrite + Send + 'static>(
    stream: RW,
    peer_addr: SocketAddr,
    state: Arc<State>,
) {
    let (reader, mut writer) = split(stream);
    let mut reader = tokio::io::BufReader::new(reader);

    let state_for_write = Arc::clone(&state);

    tokio::spawn(async move {
        let mut buf = String::with_capacity(1024);
        loop {
            buf.clear();
            let num = reader.read_line(&mut buf).await.expect("todo");
            if num == 0 {
                break;
            }
            println!("{}", buf);
        }
    });

    let state = state_for_write;
    tokio::spawn(async move {
        loop {
            let mut inbound_rx = state.inbound_rx.lock().await;

            loop {
                let (client, msg) = inbound_rx.recv().await.expect("todo");
                let data = format!("{:?} {:?}", client, msg);
                println!("{}", data);
                if let Err(_) = writer.write_all(data.as_bytes()).await {
                    break;
                }
            }
        }
    });
}
