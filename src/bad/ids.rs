use std::fmt;

// Nick routing.
//
// A... `talker` can talk. It can talk in channels, talk to other talkers directly,
// and is what people want to talk to.
//
// A connection is a tcp(/tls) socket.
//
// An account is a group of passwords, and some capabilities.
//
// We're enforcing that a connection has an account.
// A connection should probably have at least one talker associated with it,
// just so we can refer to it?
//
// A standard IRC client is represented as a single talker. We allow the account
// to connect if they can authenticate, and resume as the talker. We should probably
// disconnect people on timeout as normal, although maybe with a far smaller ping-out (30s?).
//
// Traditional services are a single connection/account, but multiple talkers, and some caps.
//
// Bridges are... a single connection/account, with multiple talkers, and no extra caps? Beyond
// the "multiple talker" cap?

// New thoughts:
// A `talker` is going to be called a `user`. A `user` has a nick (globally unique), but
// isn't that nick, 'cos they can change. A `user` can migrate between `connection`s.
// A `user` always has an `account` and a `nick`. The `account` probably doesn't change?
// `NICKSERV GROUP` would probably change the `account`, if implemented in that direction.
// A `user` is in `channel`s. Multiple `user`s can be online on the same `account`? Kinda.
// Potential confusion with the `USER` command, but we're already calling that GECOS, and
// broadly ignoring it totally. Afaik no clients let you put useful information in most of
// the fields anyway, so it's not a good way to transfer pre-auth info. Freenode pack it into
// the `PASS` command, as `PASS account:password`, which might be useful if their `NICK` rejects
// existing `NICK`s, and/or if your client sucks and sends Foo_____2 and it's hard to turn off.
// Maybe allow both? Ambiguous with : in password, but it would have to be `[valid nick]:6+`,
// which significantly reduces the number of things which need double checks. Increases the
// complexity of the auth code, though.

// Concern: Almost identical structs here, could share a Target / Ident / ?
// Concern: Is a nick different from an ident (nick!~user@host)? An unresolved ident?

#[derive(Clone, Debug)]
pub struct Nick {
    inner: String,
}

#[derive(Clone, Debug)]
pub struct ChannelName {
    /// full name, including #
    inner: String,
}

#[derive(Clone, Debug)]
pub struct HostMask {
    inner: String,
}

impl Nick {
    pub fn new<S: AsRef<str> + ToString>(from: S) -> Result<Nick, &'static str> {
        if !valid_nick(from.as_ref()) {
            return Err("banned nick");
        }

        Ok(Nick {
            inner: from.to_string(),
        })
    }
}

impl ChannelName {
    pub fn new<S: AsRef<str> + ToString>(from: S) -> Result<ChannelName, &'static str> {
        if !valid_channel(from.as_ref()) {
            return Err("banned channel");
        }

        Ok(ChannelName {
            inner: from.to_string(),
        })
    }
}

impl HostMask {
    pub fn new(raw_user_name: &str, host: &str) -> HostMask {
        let mut user_name: String = raw_user_name
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect();
        if user_name.is_empty() {
            user_name.push_str("null");
        }
        let display_host: String = host
            .chars()
            .filter(|c| c.is_alphanumeric() || c.is_ascii_punctuation())
            .collect();
        HostMask {
            inner: format!("~{}!{}", user_name, display_host),
        }
    }
}

// Concern. Will allow accidental Eq violation.
impl AsRef<str> for Nick {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

// Concern. Will allow accidental Eq violation.
impl AsRef<str> for ChannelName {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

fn valid_channel(chan: &str) -> bool {
    if !chan.starts_with('#') {
        return false;
    }

    valid_nick(&chan[1..])
}

pub fn valid_account(account: &str) -> bool {
    valid_nick(account)
}

fn valid_nick(nick: &str) -> bool {
    if nick.len() <= 1 || nick.len() >= 12 {
        return false;
    }

    if nick.contains(|c| !valid_nick_char(c)) {
        return false;
    }

    if !nick.chars().next().unwrap().is_ascii_alphabetic() {
        return false;
    }

    true
}

fn valid_nick_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_".contains(c)
}

impl PartialEq for Nick {
    fn eq(&self, other: &Nick) -> bool {
        other.inner.eq_ignore_ascii_case(&self.inner)
    }
}

impl fmt::Display for Nick {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl fmt::Display for ChannelName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}
