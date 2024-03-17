//! * https://modern.ircdocs.horse/#errunknownerror-400
//! * https://www.alien.net.au/irc/irc2numerics.html

use super::ids::Nick;
use super::OutCommand;

// Note: the horse docs use "<client>" to mean "ident", i.e. `Faux!faux@localhost`

/// horse, sending it for parse errors, and [..]
pub fn unknown_error<I: Ident>(ident: I, _command: &str, reason: &'static str) -> OutCommand {
    // <client> <command>{ <subcommand>} :<info>
    OutCommand::new("400", &[ident.as_ref(), "*", reason])
}

/// horse, sending it for invalid message targets
pub fn no_such_nick<I: Ident>(ident: I, _nick: String, reason: &'static str) -> OutCommand {
    // <client> <nickname> :No such nick/channel
    OutCommand::new("401", &[ident.as_ref(), "*", reason])
}

/// horse, sending it for invalid channel names
pub fn no_such_channel<I: Ident>(ident: I, _channel: String, reason: &'static str) -> OutCommand {
    // <client> <channel> :No such channel
    OutCommand::new("403", &[ident.as_ref(), "*", reason])
}

/// ircv3.1, using as intended, but maybe don't have the full mandatory support
pub fn invalid_cap_command<I: Ident>(
    ident: I,
    _command: String,
    reason: &'static str,
) -> OutCommand {
    // <ident> <cmd> :<reason>
    OutCommand::new("410", &[ident.as_ref(), "*", reason])
}

/// ircv3.3 "input too long" from the message-tags-3.3 draft. We're just rejecting everything.
pub fn line_too_long<I: Ident>(ident: I, reason: &'static str) -> OutCommand {
    // <ident> :<reason>
    OutCommand::new("417", &[ident.as_ref(), reason])
}

/// horse, but we also send it for some parse errors
pub fn unknown_command<I: Ident>(ident: I, _cmd: &str, reason: &'static str) -> OutCommand {
    // <client> <command> :Unknown command
    OutCommand::new("421", &[ident.as_ref(), "*", reason])
}

/// horse, sent for internal errors processing commands; motd
pub fn file_error<I: Ident>(ident: I, reason: &'static str) -> OutCommand {
    // <client> :MOTD File is missing
    OutCommand::new("424", &[ident.as_ref(), reason])
}

/// horse, possibly used as intended!
pub fn erroneous_nickname<I: Ident>(ident: I, _nick: String, reason: &'static str) -> OutCommand {
    // <client> <nick> :Erroneous nickname
    OutCommand::new("432", &[ident.as_ref(), "*", reason])
}

/// horse, possibly used as intended!
pub fn nickname_in_use<I: Ident>(ident: I, nick: &Nick, reason: &'static str) -> OutCommand {
    // <client> <nick> :Nickname is already in use
    OutCommand::new("432", &[ident.as_ref(), nick.as_ref(), reason])
}

/// horse, including invalid pre-auth command parsing
pub fn not_registered<I: Ident>(ident: I, reason: &'static str) -> OutCommand {
    // <client> :<reason>
    OutCommand::new("451", &[ident.as_ref(), reason])
}

/// horse, including pass missing
pub fn password_mismatch<I: Ident>(ident: I, reason: &'static str) -> OutCommand {
    // <client> :Password incorrect
    OutCommand::new("464", &[ident.as_ref(), reason])
}

/// KineIRCd. Most IRCds pass-through. I don't agree.
pub fn bad_char_encoding<I: Ident>(ident: I, _cmd: &str, reason: &'static str) -> OutCommand {
    // <client> <command> <charset> :<info>
    OutCommand::new("980", &[ident.as_ref(), "*", "utf-8", reason])
}

pub trait Ident {
    fn as_ref(&self) -> &str;
}

impl Ident for () {
    #[inline]
    fn as_ref(&self) -> &str {
        "*"
    }
}
