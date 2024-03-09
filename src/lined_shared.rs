use anyhow::Result;
use bincode::config as bc;
use bincode::de::{BorrowDecoder, Decoder};
use bincode::enc::Encoder;
use bincode::error::DecodeError;
use uuid::Uuid;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Uid(pub Uuid);

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
