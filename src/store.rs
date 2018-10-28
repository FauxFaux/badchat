use std::time;

use cast::i64;
use failure::Error;
use pbkdf2::pbkdf2_check;
use pbkdf2::pbkdf2_simple;
use pbkdf2::CheckError;
use rusqlite::types::ToSql;
use rusqlite::Connection;
use rusqlite::Transaction;

use crate::ChannelId;

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
        // committed inside `create_user`, not sure I like that?
        let mut tx = self.conn.transaction()?;

        let account_id = match load_id(&tx, "select account_id from nick where nick=?", &[nick])? {
            Some(val) => val,
            None => {
                let user = create_user(tx, nick, pass)?;
                return Ok(Some(user));
            }
        };

        for hashed in tx
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

    pub fn load_channel(&mut self, name: &str) -> Result<ChannelId, Error> {
        let tx = self.conn.transaction()?;
        Ok(ChannelId(
            match load_id(&tx, "select id from channel where name=?", &[name])? {
                Some(id) => id,
                None => create_channel(tx, name)?,
            },
        ))
    }
}

fn load_id<P>(tx: &Transaction, query: &'static str, params: P) -> Result<Option<i64>, Error>
where
    P: IntoIterator,
    P::Item: ToSql,
{
    let mut stat = tx.prepare_cached(query)?;
    let mut query = stat.query_map(params, |row| row.get::<_, i64>(0))?;
    Ok(if let Some(res) = query.next() {
        ensure!(query.next().is_none(), "unexpected multiple rows");
        Some(res?)
    } else {
        None
    })
}

fn create_user(tx: Transaction, nick: &str, pass: &str) -> Result<i64, Error> {
    let now = unix_time();

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

fn create_channel(tx: Transaction, name: &str) -> Result<i64, Error> {
    let now = unix_time();

    tx.execute(
        "insert into channel (name, creation_time, mode) values (?,?,?)",
        &[&name as &ToSql, &now, &""],
    )?;

    let channel_id = tx.last_insert_rowid();

    tx.commit()?;

    info!("created channel {:?}", name);

    return Ok(channel_id);
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
