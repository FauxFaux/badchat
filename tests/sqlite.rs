use anyhow::Error;
use rusqlite::Connection;

/// quick panic about: If the first byte of the payload is 0x00, 0x01, or 0x02
/// then that byte is ignored and the remaining bytes are UTF8, UTF16le, or UTF16be
/// respectively. If the first byte is 0x03 or larger, then the entire string including
/// the first byte is UTF8. An empty string consists of the header code 22 and no payload.
#[test]
fn round_trip() -> Result<(), Error> {
    let conn = Connection::open_in_memory()?;
    conn.execute("create table strings (val text not null)", [])?;
    let mut trunc = conn.prepare("delete from strings")?;
    let mut write = conn.prepare("insert into strings (val) values (?)")?;
    let mut read = conn.prepare("select val from strings")?;
    for c in 1..255 {
        trunc.execute([])?;

        let mut before = String::with_capacity(16);
        let c_as_char = std::char::from_u32(c).expect("from_u32");
        before.push(c_as_char);
        before.push(c_as_char);
        before.push(c_as_char);

        write.execute(&[&before])?;
        let after: String = read.query_row([], |row| row.get(0))?;
        assert_eq!(before, after);
    }
    Ok(())
}
