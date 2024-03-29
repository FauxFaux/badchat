use anyhow::Result;
use bincode::de::{BorrowDecoder, Decoder};
use bincode::enc::Encoder;
use bincode::error::DecodeError;
use bincode::{config as bc, Decode, Encode};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Uid(pub Uuid);

#[derive(bincode::Encode, bincode::Decode, Debug, PartialEq, Eq, Hash)]
pub enum FromLined {
    Message(Uid, MessageIn),
}

#[derive(bincode::Encode, bincode::Decode, Debug, PartialEq, Eq, Hash)]
pub enum MessageIn {
    Data(String),
    Connected(SocketAddr),
    Overflow,
    InvalidUtf8,
    Closed,
}

#[derive(bincode::Encode, bincode::Decode, Debug)]
pub enum ToLined {
    Message(Uid, MessageOut),
}

#[derive(bincode::Encode, bincode::Decode, Debug)]
pub enum MessageOut {
    Data(String),
    FlushAndClose,
    // not implemented
    Terminate,
}

impl bincode::Encode for Uid {
    fn encode<E: Encoder>(
        &self,
        e: &mut E,
    ) -> std::result::Result<(), bincode::error::EncodeError> {
        self.0.as_bytes().encode(e)
    }
}

impl bincode::Decode for Uid {
    fn decode<D: Decoder>(d: &mut D) -> std::result::Result<Self, bincode::error::DecodeError> {
        Ok(Uid(Uuid::from_bytes(<[u8; 16]>::decode(d)?)))
    }
}

impl<'de> bincode::BorrowDecode<'de> for Uid {
    fn borrow_decode<D: BorrowDecoder<'de>>(d: &mut D) -> std::result::Result<Self, DecodeError> {
        use bincode::Decode;
        Ok(Uid(Uuid::from_bytes(<[u8; 16]>::decode(d)?)))
    }
}

const CONFIG: bc::Configuration<bc::LittleEndian, bc::Fixint, bc::NoLimit> = bc::standard()
    .with_no_limit()
    .with_little_endian()
    .with_fixed_int_encoding();

pub fn encode(v: impl bincode::Encode) -> Result<Vec<u8>> {
    Ok(bincode::encode_to_vec(v, CONFIG)?)
}

pub fn decode<T: bincode::Decode>(v: &[u8]) -> Result<T> {
    let (a, b) = bincode::decode_from_slice(&v, CONFIG)?;
    ensure!(b == v.len(), "not all bytes were read");
    Ok(a)
}

/// not cancellation safe; may have read from reader
pub async fn read_message<T: Decode>(
    buf: &mut Vec<u8>,
    mut r: impl AsyncRead + Unpin,
) -> Result<T> {
    let len = usize::from(r.read_u16_le().await?);
    buf.resize(len, 0);
    r.read_exact(buf).await?;
    decode(&buf)
}

pub async fn write_message<T: Encode>(mut w: impl AsyncWrite + Unpin, v: T) -> Result<()> {
    let buf = encode(v)?;
    w.write_u16_le(u16::try_from(buf.len())?).await?;
    w.write_all(&buf).await?;
    Ok(())
}
