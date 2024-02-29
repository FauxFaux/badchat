use std::fs;
use std::io;
use std::sync::Arc;

use anyhow::Context as _;
use anyhow::Error;

fn load_certs(filename: &str) -> Result<Vec<()>, Error> {
    let certfile =
        fs::File::open(filename).with_context(|| format_err!("cannot open certificate file"))?;
    let mut reader = io::BufReader::new(certfile);
    unimplemented!("load_certs")
}

fn load_private_key(filename: &str) -> Result<(), Error> {
    let rsa_keys = {
        let keyfile = fs::File::open(filename)
            .with_context(|| format_err!("cannot open private key file"))?;
        let mut reader = io::BufReader::new(keyfile);
        unimplemented!("load_private_key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename)
            .with_context(|| format_err!("cannot open private key file"))?;
        let mut reader = io::BufReader::new(keyfile);
    };
}

pub fn make_default_tls_config() -> Result<rustls::ServerConfig, Error> {
    unimplemented!()
}
