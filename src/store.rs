use std::time;

use cast::i64;
use failure::Error;
use pbkdf2::pbkdf2_check;
use pbkdf2::pbkdf2_simple;
use pbkdf2::CheckError;
use rusqlite::types::ToSql;
use rusqlite::Connection;

pub struct Store {
    conn: Connection,
}

/// ..for new passwords. Low by modern standards, but
/// also we're exposed like crazy.
const PBKDF2_ITERATION_COUNT: u32 = 4096;

impl Store {
    pub fn new() -> Result<Store, Error> {
        Ok(Store {
            conn: Connection::open("badchat.db")?,
        })
    }

    pub fn user(&mut self, nick: &str, pass: &str) -> Result<Option<i64>, Error> {
        // TODO: so much borrow/option sadness
        let account_id = if let Some(res) = self
            .conn
            .prepare_cached("select account_id from nick where nick=?")?
            .query_map(&[nick], |row| row.get::<_, i64>(0))?
            .next()
        {
            Some(res?)
        } else {
            None
        };

        // BORROW CHECKER
        let account_id = match account_id {
            Some(val) => val,
            None => return Ok(Some(self.create_user(nick, pass)?)),
        };

        for hashed in self
            .conn
            .prepare_cached("select pass from account_pass where account_id=?")?
            .query_map(&[account_id], |row| row.get::<_, String>(0))?
        {
            let hashed = hashed?;
            if check_pass(pass, &hashed)? {
                return Ok(Some(account_id));
            }
        }

        return Ok(None);
    }

    fn create_user(&mut self, nick: &str, pass: &str) -> Result<i64, Error> {
        let now = unix_time();
        let tx = self.conn.transaction()?;

        tx.execute("insert into account (creation_time) values (?)", &[now])?;

        let account_id = tx.last_insert_rowid();

        tx.execute(
            "insert into nick (nick, account_id) values (?,?)",
            &[&nick as &ToSql, &account_id],
        )?;

        tx.execute(
            "insert into account_pass (account_id, pass) values (?,?)",
            &[
                &account_id as &ToSql,
                &pbkdf2_simple(pass, PBKDF2_ITERATION_COUNT)?,
            ],
        )?;

        tx.commit()?;
        info!("created user {:?}", nick);

        return Ok(account_id);
    }
}

fn check_pass(pass: &str, hashed: &str) -> Result<bool, Error> {
    match pbkdf2_check(pass, hashed) {
        Ok(()) => Ok(true),
        Err(CheckError::HashMismatch) => Ok(false),
        Err(e) => bail!(e),
    }
}

fn unix_time() -> i64 {
    i64(time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap()
        .as_secs())
    .expect("current time out of range")
}
