use std::fmt;
use std::time;

use anyhow::Error;
use rusqlite::types::ToSql;
use rusqlite::Transaction;
use rusqlite::{Connection, Params};

use super::ids::ChannelName;
use super::ChannelId;
use super::Pass;
use crate::pbkdf2::pbkdf2_check;
use crate::pbkdf2::pbkdf2_simple;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn new() -> Result<Store, Error> {
        Ok(Store {
            conn: Connection::open("badchat.db")?,
        })
    }

    pub fn account(&mut self, pass: &Pass) -> Option<i64> {
        // committed inside `create_account`, not sure I like that?
        let tx = self.conn.transaction().unwrap_system();

        let account_id = match load_id(
            &tx,
            "select account_id from account where name=?",
            &[&pass.account],
        ) {
            Some(val) => val,
            None => {
                let user = create_account(tx, pass);
                return Some(user);
            }
        };

        for hashed in tx
            .prepare_cached("select pass from account_pass where account_id=?")
            .unwrap_system()
            .query_map([account_id], |row| row.get::<_, String>(0))
            .unwrap_system()
        {
            let hashed = hashed.unwrap_system();
            if check_pass(&pass.pass, &hashed) {
                return Some(account_id);
            }
        }

        None
    }

    pub fn load_channel(&mut self, name: &ChannelName) -> ChannelId {
        let tx = self.conn.transaction().unwrap_system();
        ChannelId(
            match load_id(&tx, "select id from channel where name=?", &[name.as_ref()]) {
                Some(id) => id,
                None => create_channel(tx, name),
            },
        )
    }
}

fn load_id<P>(tx: &Transaction, query: &'static str, params: P) -> Option<i64>
where
    P: IntoIterator + Params,
    P::Item: ToSql,
{
    let mut stat = tx.prepare_cached(query).unwrap_system();
    let mut query = stat
        .query_map(params, |row| row.get::<_, i64>(0))
        .unwrap_system();
    if let Some(res) = query.next() {
        assert!(query.next().is_none(), "unexpected multiple rows");
        Some(res.unwrap_system())
    } else {
        None
    }
}

fn create_account(tx: Transaction, pass: &Pass) -> i64 {
    let now = unix_time();

    tx.execute(
        "insert into account (name, creation_time) values (?,?)",
        &[&pass.account as &dyn ToSql, &now],
    )
    .unwrap_system();

    let account_id = tx.last_insert_rowid();

    tx.execute(
        "insert into account_pass (account_id, pass) values (?,?)",
        &[
            &account_id as &dyn ToSql,
            &pbkdf2_simple(&pass.pass).unwrap_system(),
        ],
    )
    .unwrap_system();

    tx.commit().unwrap_system();

    info!("created account {:?}", pass.account);

    account_id
}

fn create_channel(tx: Transaction, name: &ChannelName) -> i64 {
    let now = unix_time();

    tx.execute(
        "insert into channel (name, creation_time, mode) values (?,?,?)",
        &[&name.as_ref() as &dyn ToSql, &now, &""],
    )
    .unwrap_system();

    let channel_id = tx.last_insert_rowid();

    tx.commit().unwrap_system();

    info!("created channel {:?}: {}", name, channel_id);

    channel_id
}

fn check_pass(pass: &str, hashed: &str) -> bool {
    match pbkdf2_check(pass, hashed) {
        Ok(v) => v,
        Err(e) => {
            error!("pass parsing failed: {:?}: {:?}", hashed, e);
            false
        }
    }
}

fn unix_time() -> i64 {
    i64::try_from(
        time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .expect("current time out of range")
}

trait SystemError<T, E> {
    /// unwrap, but this is expected if there's a problem with the system,
    /// but not e.g. user input errors
    fn unwrap_system(self) -> T;
}

impl<T, E: fmt::Debug> SystemError<T, E> for Result<T, E> {
    fn unwrap_system(self) -> T {
        self.unwrap()
    }
}
