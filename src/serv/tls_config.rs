use std::fs;
use std::io;
use std::sync::Arc;

use anyhow::Context as _;
use anyhow::Error;
use rustls::NoClientAuth;

fn load_certs(filename: &str) -> Result<Vec<rustls::Certificate>, Error> {
    let certfile =
        fs::File::open(filename).with_context(|| format_err!("cannot open certificate file"))?;
    let mut reader = io::BufReader::new(certfile);
    Ok(rustls::internal::pemfile::certs(&mut reader)
        .map_err(|()| format_err!("pemfile certs reader"))?)
}

fn load_private_key(filename: &str) -> Result<rustls::PrivateKey, Error> {
    let rsa_keys = {
        let keyfile = fs::File::open(filename)
            .with_context(|| format_err!("cannot open private key file"))?;
        let mut reader = io::BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .map_err(|()| format_err!("file contains invalid rsa private key"))?
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename)
            .with_context(|| format_err!("cannot open private key file"))?;
        let mut reader = io::BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader).map_err(|_| {
            format_err!("file contains invalid pkcs8 private key (encrypted keys not supported)")
        })?
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        Ok(pkcs8_keys[0].clone())
    } else {
        assert!(!rsa_keys.is_empty());
        Ok(rsa_keys[0].clone())
    }
}

pub fn make_default_tls_config() -> Result<rustls::ServerConfig, Error> {
    let mut config = rustls::ServerConfig::new(NoClientAuth::new());
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let certs = load_certs("localhost.crt")?;
    let privkey = load_private_key("localhost.key")?;
    config
        .set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .with_context(|| format_err!("bad certificates/private key"))?;

    Ok(config)
}
