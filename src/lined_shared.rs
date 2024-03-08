use anyhow::Result;
use bincode::config as bc;

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
