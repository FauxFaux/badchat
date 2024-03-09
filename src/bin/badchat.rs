use anyhow::{anyhow, Result};
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    match env::args().nth(1).as_deref() {
        Some("lined") => return badchat::lined::main().await,
        _ => (),
    }
    Err(anyhow!("usage: badchat lined"))
}
