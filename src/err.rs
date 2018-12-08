use crate::ids;
use crate::OutCommand;

/// RFC1459, sending it for parse errors, and [..]
pub fn unknown_error(reason: &'static str) -> OutCommand {
    // <command> [<?>] :<info>
    OutCommand::new("400", &["*", "*", reason])
}

/// RFC1459, sending it for invalid message targets
pub fn no_such_nick(_nick: String, reason: &'static str) -> OutCommand {
    // <nick> :<reason>
    OutCommand::new("401", &["*", reason])
}

/// RFC1459, sending it for invalid channel names
pub fn no_such_channel(_channel: String, reason: &'static str) -> OutCommand {
    // <channel> :<reason>
    OutCommand::new("403", &["*", reason])
}

/// ircv3.1, using as intended, but maybe don't have the full mandatory support
pub fn invalid_cap_command(
    _nick: Option<ids::Nick>,
    _command: String,
    reason: &'static str,
) -> OutCommand {
    // <nick> <cmd> :<reason>
    OutCommand::new("410", &["*", "*", reason])
}

/// "input too long" from the message-tags-3.3 draft. Like with encoding, we're just rejecting
pub fn line_too_long(reason: &'static str) -> OutCommand {
    // ?
    // :<reason>
    OutCommand::new("417", &[reason])
}

/// RFC1459, but we also send it for some parse errors
pub fn unknown_command(_cmd: String, reason: &'static str) -> OutCommand {
    // <command> :<reason>
    OutCommand::new("421", &["*", reason])
}

/// RFC1459, sent for internal errors processing commands; motd
pub fn file_error(reason: &'static str) -> OutCommand {
    // :<reason>
    OutCommand::new("424", &[reason])
}

/// RFC1459, possibly used as intended!
pub fn erroneous_nickname(_nick: String, reason: &'static str) -> OutCommand {
    // <nick> :<reason>
    OutCommand::new("432", &["*", reason])
}

/// RFC1459, including invalid pre-auth command parsing
pub fn not_registered(reason: &'static str) -> OutCommand {
    // :<reason>
    OutCommand::new("451", &[reason])
}

/// RFC1459, including pass missing
pub fn password_mismatch(reason: &'static str) -> OutCommand {
    // :<reason>
    OutCommand::new("464", &[reason])
}

/// KineIRCd. Most IRCds pass-through. I don't agree.
pub fn bad_char_encoding(_cmd: String, reason: &'static str) -> OutCommand {
    // <command> <charset> :<info>
    OutCommand::new("980", &["*", "utf-8", reason])
}
