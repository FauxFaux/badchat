use pbkdf2::pbkdf2_check;
use pbkdf2::pbkdf2_simple;
use pbkdf2::CheckError;

use failure::Error;
use rusqlite::Connection;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn new() -> Result<Store, Error> {
        Ok(Store {
            conn: Connection::open("badchat.db")?,
        })
    }

    pub fn user(&self, nick: &str, pass: &str) -> Result<i64, Error> {
        let account_id: i64 =
            self.conn
                .query_row("select account_id from nick where nick=?", &[nick], |row| {
                    row.get(0)
                })?;
        let mut stat = self
            .conn
            .prepare("select pass from account_pass where account_id=?")?;

        for hashed in stat.query_map(&[account_id], |row| row.get::<_, String>(0))? {
            let hashed = hashed?;
            if check_pass(pass, &hashed)? {
                return Ok(account_id);
            }
        }

        bail!("user not found")
    }
}

fn check_pass(pass: &str, hashed: &str) -> Result<bool, Error> {
    match pbkdf2_check(pass, hashed) {
        Ok(()) => Ok(true),
        Err(CheckError::HashMismatch) => Ok(false),
        Err(e) => bail!(e),
    }
}
