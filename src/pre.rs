use crate::ids::Nick;
use crate::proto::Command;
use crate::proto::ParsedMessage as Message;
use crate::ErrorCode;
use crate::PreAuth;
use crate::PreAuthPing;

use crate::render_ping;
use crate::render_pong;

#[derive(Clone, Debug)]
pub enum PreAuthOp {
    Done,
    Output(Vec<String>),
    Error(String),
}

/// https://modern.ircdocs.horse/#connection-registration
pub fn work_pre_auth(message: &Message, state: &mut PreAuth) -> PreAuthOp {
    match message.command() {
        Ok(Command::CapLs(_version)) => {
            state.sending_caps = true;
            return PreAuthOp::Output(vec!["CAP * LS :".to_string()]);
        }
        Ok(Command::CapEnd) => {
            state.sending_caps = false;
        }
        Ok(Command::Pass(pass)) => state.pass = Some(pass.to_string()),
        Ok(Command::Nick(nick)) => {
            state.nick = Some(match Nick::new(nick) {
                Ok(nick) => nick,
                Err(_reason) => {
                    return PreAuthOp::Output(vec![format!(
                        "{:03} * :invalid nickname; ascii letters, numbers, _. 2-12",
                        ErrorCode::ErroneousNickname.into_numeric()
                    )]);
                }
            });

            if state.ping == PreAuthPing::WaitingForNick {
                state.ping = PreAuthPing::WaitingForPong;
                return PreAuthOp::Output(vec![render_ping(&format!("{:08x}", state.ping_token.0))]);
            }
        }
        Ok(Command::User(ident, _mode, real_name)) => {
            state.gecos = Some((ident.to_string(), real_name.to_string()))
        }
        Ok(Command::Ping(arg)) => return PreAuthOp::Output(vec![render_pong(arg)]),
        Ok(Command::Pong(ref arg))
            if PreAuthPing::WaitingForPong == state.ping
                && u64::from_str_radix(arg, 16) == Ok(state.ping_token.0) =>
        {
            state.ping = PreAuthPing::Complete
        }
        Ok(Command::Other(ref raw, ..)) if is_http_verb(raw) => {
            info!("http command on channel: {:?}", raw);
            // TODO: is it worth sending them anything?
            return PreAuthOp::Error(String::new());
        }
        Ok(Command::CapUnknown) => {
            return PreAuthOp::Output(vec![format!(
                "{:03} * * :invalid cap command",
                ErrorCode::InvalidCapCommand.into_numeric()
            )]);
        }
        _other => {
            return PreAuthOp::Output(vec![format!(
                "{:03} * * :invalid pre-auth command",
                ErrorCode::NotRegistered.into_numeric()
            )]);
        }
    }

    if !state.is_client_preamble_done() {
        info!("waiting for more from client...");
        return PreAuthOp::Output(Vec::new());
    }

    if state.pass.is_none() {
        return PreAuthOp::Error(format!(
            concat!(
                "{:03} * :",
                "You must provide a password. ",
                "For an unregistered nick, any password is fine! ",
                "I'll just make you a new account."
            ),
            ErrorCode::PasswordMismatch.into_numeric()
        ));
    }

    PreAuthOp::Done
}

fn is_http_verb(word: &str) -> bool {
    for verb in &["get", "connect", "post", "put", "delete", "patch"] {
        if word.eq_ignore_ascii_case(verb) {
            return true;
        }
    }

    false
}
