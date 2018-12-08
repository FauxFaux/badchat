use crate::ids::Nick;
use crate::proto::Command;
use crate::proto::ParsedMessage as Message;
use crate::ErrorCode;
use crate::OutCommand;
use crate::PreAuth;
use crate::PreAuthPing;

#[derive(Clone, Debug)]
pub enum PreAuthOp {
    Done,
    Output(Vec<OutCommand>),
    Error(OutCommand),
}

/// https://modern.ircdocs.horse/#connection-registration
pub fn work_pre_auth(message: &Message, state: &mut PreAuth) -> PreAuthOp {
    match message.command() {
        Ok(Command::CapLs(_version)) => {
            state.sending_caps = true;
            return PreAuthOp::Output(vec![OutCommand::new("CAP", &["*", "LS", ""])]);
        }
        Ok(Command::CapEnd) => {
            state.sending_caps = false;
        }
        Ok(Command::Pass(pass)) => state.pass = Some(pass.to_string()),
        Ok(Command::Nick(nick)) => {
            state.nick = Some(match Nick::new(nick) {
                Ok(nick) => nick,
                Err(_reason) => {
                    return PreAuthOp::Output(vec![OutCommand::new(
                        ErrorCode::ErroneousNickname.into_numeric(),
                        &["*", "invalid nickname; ascii letters, numbers, _. 2-12"],
                    )]);
                }
            });

            if state.ping == PreAuthPing::WaitingForNick {
                state.ping = PreAuthPing::WaitingForPong;
                return PreAuthOp::Output(vec![OutCommand::new(
                    "PING",
                    &[format!("{:08x}", state.ping_token.0)],
                )]);
            }
        }
        Ok(Command::User(ident, _mode, real_name)) => {
            state.gecos = Some((ident.to_string(), real_name.to_string()))
        }
        Ok(Command::Ping(arg)) => return PreAuthOp::Output(vec![OutCommand::new("PONG", &[arg])]),
        Ok(Command::Pong(ref arg))
            if PreAuthPing::WaitingForPong == state.ping
                && u64::from_str_radix(arg, 16) == Ok(state.ping_token.0) =>
        {
            state.ping = PreAuthPing::Complete
        }
        Ok(Command::Other(ref raw, ..)) if is_http_verb(raw) => {
            info!("http command on channel: {:?}", raw);
            // TODO: is it worth sending them anything?
            return PreAuthOp::Error(OutCommand::new("999", &["no thanks"]));
        }
        Ok(Command::CapUnknown) => {
            return PreAuthOp::Output(vec![OutCommand::new(
                ErrorCode::InvalidCapCommand.into_numeric(),
                &["*", "*", "invalid cap command"],
            )]);
        }
        _other => {
            return PreAuthOp::Output(vec![OutCommand::new(
                ErrorCode::NotRegistered.into_numeric(),
                &["*", "*", "invalid pre-auth command"],
            )]);
        }
    }

    if !state.is_client_preamble_done() {
        info!("waiting for more from client...");
        return PreAuthOp::Output(Vec::new());
    }

    if state.pass.is_none() {
        return PreAuthOp::Error(OutCommand::new(
            ErrorCode::PasswordMismatch.into_numeric(),
            &[
                "*",
                concat!(
                    "",
                    "You must provide a password. ",
                    "For an unregistered nick, any password is fine! ",
                    "I'll just make you a new account."
                ),
            ],
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
