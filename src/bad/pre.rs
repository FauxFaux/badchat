use super::err;
use super::ids::valid_account;
use super::ids::Nick;
use super::proto::Command;
use super::proto::ParsedMessage as Message;
use super::OutCommand;
use super::Pass;
use super::PingToken;
use super::PreAuth;
use super::PreAuthPing;

#[derive(Clone, Debug)]
pub enum PreAuthOp {
    Done,
    Output(Vec<OutCommand>),
    Error(OutCommand),
    Ping(PingToken),
}

/// https://modern.ircdocs.horse/#connection-registration
pub fn work_pre_auth(message: &Message, state: &mut PreAuth) -> PreAuthOp {
    match message.command() {
        Ok(Command::CapLs(_version)) => {
            state.sending_caps = true;
            return PreAuthOp::Output(vec![OutCommand::new(
                "CAP",
                &["*", "LS", "draft/message-tags-0.2 server-time"],
            )]);
        }
        Ok(Command::CapEnd) => {
            state.sending_caps = false;
        }
        Ok(Command::Pass(pass)) if state.pass.is_none() => {
            let password_parse_error = PreAuthOp::Output(vec![err::password_mismatch(
                (),
                concat!(
                    "Your password must start with your account name, and a colon. ",
                    "e.g. randall:correct_horse_battery_staple",
                ),
            )]);

            if let Some(split) = pass.find(':') {
                let (account, pass) = pass.split_at(split);
                if !valid_account(account) || pass.len() < 6 {
                    return password_parse_error;
                }
                state.pass = Some(Pass {
                    account: account.to_string(),
                    pass: pass.to_string(),
                })
            } else {
                return password_parse_error;
            }
        }
        Ok(Command::Nick(nick)) => {
            state.nick = Some(match Nick::new(nick) {
                Ok(nick) => nick,
                Err(_reason) => {
                    return PreAuthOp::Output(vec![err::erroneous_nickname(
                        (),
                        "*".to_string(),
                        "invalid nickname; ascii letters, numbers, _. 2-12",
                    )]);
                }
            });

            if state.ping == PreAuthPing::WaitingForNick {
                state.ping = PreAuthPing::WaitingForPong;
                return PreAuthOp::Ping(state.ping_token);
            }
        }
        Ok(Command::User(ident, _mode, real_name)) => {
            state.gecos = Some((ident.to_string(), real_name.to_string()))
        }
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
            return PreAuthOp::Output(vec![err::invalid_cap_command(
                (),
                "*".to_string(),
                "invalid cap command",
            )]);
        }
        Ok(Command::Ping(_)) => unreachable!("ping handled as link management"),
        _other => {
            return PreAuthOp::Output(vec![err::not_registered((), "invalid pre-auth command")]);
        }
    }

    if !state.is_client_preamble_done() {
        info!("waiting for more from client...");
        return PreAuthOp::Output(Vec::new());
    }

    if state.pass.is_none() {
        return PreAuthOp::Error(err::password_mismatch(
            (),
            concat!(
                "You must provide a password. ",
                "For an unregistered nick, any password is fine! ",
                "I'll just make you a new account."
            ),
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
