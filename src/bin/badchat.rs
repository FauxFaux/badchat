use anyhow::{anyhow, Result};
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    match env::args().nth(1) {
        Some(arg) => match arg.as_str() {
            "lined" => return badchat::lined::main().await,
            _ => (),
        },
        None => (),
    }
    Err(anyhow!("usage: badchat lined"))
}
