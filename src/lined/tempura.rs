use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::Path;

use rustls_pemfile::{certs, pkcs8_private_keys};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use uuid::{NoContext, Uuid};

pub fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

pub fn load_keys(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput,
                                      "no rsa keys found (only pkcs8 / BEGIN PRIVATE KEY, i.e. not pkcs1 / BEGIN RSA PRIVATE KEY, is supported)"))?
        .map(Into::into)
}

pub fn uuid() -> Uuid {
    Uuid::new_v7(uuid::Timestamp::now(NoContext))
}

pub fn add_keepalives(stream: &tokio::net::TcpStream) -> anyhow::Result<()> {
    use std::time::Duration;

    let sock_ref = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(60));
    sock_ref.set_tcp_keepalive(&ka)?;
    Ok(())
}
