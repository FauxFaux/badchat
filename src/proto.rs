use std::ops::Range;

use crate::ids::Nick;

#[derive(Copy, Clone, Debug)]
pub enum Command<'s> {
    Pass(&'s str),
    Nick(&'s str),

    Ping(&'s str),
    Pong(&'s str),

    /// user, mode, [*], real-name
    User(&'s str, &'s str, &'s str),

    /// channel[,channel] key[,key] real-name
    Join(&'s str, Option<&'s str>, Option<&'s str>),

    /// dest, message
    Privmsg(&'s str, &'s str),

    Quit(Option<&'s str>),

    /// version supported
    CapLs(Option<&'s str>),
    CapEnd,
    /// we need to send a different error response to a normal unknown command
    CapUnknown,

    Other(&'s str),
}

type SubStr = Range<usize>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMessage {
    buf: String,
    tags: Option<SubStr>,
    source: Option<SubStr>,
    cmd: SubStr,
    args: Option<SubStr>,
}

pub struct ParsedArgs<'b> {
    buf: &'b str,
    pos: usize,
}

// TODO: not sure it's clearer to have this not in terms of a generic
// TODO: iterator, which understands the two different :-prefixed arguments
pub fn parse_message(from: &str) -> Result<ParsedMessage, &'static str> {
    if from.starts_with(' ') {
        return Err("whitespace start");
    }

    // TODO: colours
    // Perfectly happy with this eliminating tab, etc.
    if from.contains(|c: char| !allowed_char(c)) {
        return Err("banned characters");
    }

    let mut here = 0;

    let mut tags = None;
    if from.starts_with('@') {
        let end = from.find(' ').ok_or("only tags")?;

        // 1: drop the colon
        // end is valid, it's just before a space
        tags = Some((1..end).into());
        here = end;
    }

    // technically there should only be one space, but I'm going to allow it
    while from[here..].starts_with(' ') {
        // valid: there was a ascii space at the start
        here += 1;
    }

    let remaining = &from[here..];
    let mut source = None;
    if remaining.starts_with(':') {
        let end = remaining.find(' ').ok_or("only source")?;
        source = Some((here + 1..here + end).into());
        here += end;
    }

    while from[here..].starts_with(' ') {
        here += 1;
    }

    let cmd;
    {
        let remaining = &from[here..];
        let end = remaining.find(' ').unwrap_or_else(|| remaining.len());
        cmd = SubStr::from(here..here + end);
        here += end + 1;
    };

    let args = if here < from.len() {
        Some((here..from.len()).into())
    } else {
        None
    };

    if cmd.start >= cmd.end {
        return Err("empty command");
    }

    Ok(ParsedMessage {
        buf: from.to_string(),
        tags,
        source,
        cmd,
        args,
    })
}

#[inline]
fn allowed_char(c: char) -> bool {
    match c {
        '\x01' => true, // /me
        '\x02' => true, // bold
        '\x03' => true, // colour
        '\x0f' => true, // reset formatting
        '\x16' => true, // invert
        '\x1d' => true, // italic
        '\x1f' => true, // underlined
        o if o >= ' ' => true,
        _ => false,
    }
}

impl ParsedMessage {
    fn tags_str(&self) -> Option<&str> {
        self.tags.as_ref().map(|v| &self.buf[v.clone()])
    }

    fn source_str(&self) -> Option<&str> {
        self.source.as_ref().map(|v| &self.buf[v.clone()])
    }

    fn cmd_str(&self) -> &str {
        &self.buf[self.cmd.clone()]
    }

    fn args_str(&self) -> Option<&str> {
        self.args.as_ref().map(|v| &self.buf[v.clone()])
    }

    pub fn args_iter(&self) -> ParsedArgs {
        ParsedArgs {
            buf: self.args_str().unwrap_or(""),
            pos: 0,
        }
    }

    fn args(&self) -> ShortArgs {
        let mut it = self.args_iter();
        let first = match it.next() {
            Some(val) => val,
            None => return ShortArgs::Zero,
        };

        let second = match it.next() {
            Some(val) => val,
            None => return ShortArgs::One(first),
        };

        let third = match it.next() {
            Some(val) => val,
            None => return ShortArgs::Two(first, second),
        };

        let fourth = match it.next() {
            Some(val) => val,
            None => return ShortArgs::Three(first, second, third),
        };

        match it.next() {
            None => ShortArgs::Four(first, second, third, fourth),
            Some(_) => ShortArgs::More,
        }
    }

    pub fn source_nick(&self) -> Result<Option<Nick>, &'static str> {
        let src = match self.source_str() {
            Some(src) => src,
            None => return Ok(None),
        };

        let bang = match src.find('!') {
            Some(bang) => bang,
            None => return Err("no bang"),
        };

        if 0 == bang {
            return Err("no nick before bang");
        }

        Ok(Some(Nick::new(&src[..bang])?))
    }

    pub fn command(&self) -> Result<Command, &'static str> {
        let cmd = self.cmd_str();
        if cmd.contains(|c: char| !c.is_ascii_alphabetic()) {
            Err("commands are made of letters")
        } else if cmd.eq_ignore_ascii_case("PRIVMSG") {
            match self.args() {
                ShortArgs::Two(dest, msg) => Ok(Command::Privmsg(dest, msg)),
                _ => Err("PRIVMSG takes exactly two args"),
            }
        } else if cmd.eq_ignore_ascii_case("NICK") {
            match self.args() {
                ShortArgs::One(arg) => Ok(Command::Nick(arg)),
                _ => Err("NICK takes exactly one arg"),
            }
        } else if cmd.eq_ignore_ascii_case("PING") {
            match self.args() {
                ShortArgs::One(arg) => Ok(Command::Ping(arg)),
                _ => Err("PING takes exactly one arg (non-standard)"),
            }
        } else if cmd.eq_ignore_ascii_case("PONG") {
            match self.args() {
                ShortArgs::One(arg) => Ok(Command::Pong(arg)),
                _ => Err("PONG takes exactly one arg (non-standard)"),
            }
        } else if cmd.eq_ignore_ascii_case("USER") {
            match self.args() {
                ShortArgs::Four(user, mode, _star, real_name) => {
                    Ok(Command::User(user, mode, real_name))
                }
                _ => Err("USER takes exactly four args (user, mode, *, real name)"),
            }
        } else if cmd.eq_ignore_ascii_case("PASS") {
            match self.args() {
                ShortArgs::One(arg) => Ok(Command::Pass(arg)),
                _ => Err("PASS takes exactly one arg"),
            }
        } else if cmd.eq_ignore_ascii_case("QUIT") {
            match self.args() {
                ShortArgs::Zero => Ok(Command::Quit(None)),
                ShortArgs::One(arg) => Ok(Command::Quit(Some(arg))),
                _ => Err("QUIT takes one optional arg"),
            }
        } else if cmd.eq_ignore_ascii_case("JOIN") {
            match self.args() {
                ShortArgs::One(channels) => Ok(Command::Join(channels, None, None)),
                ShortArgs::Two(channels, keys) => Ok(Command::Join(channels, Some(keys), None)),
                ShortArgs::Three(channels, keys, real_name) => {
                    Ok(Command::Join(channels, Some(keys), Some(real_name)))
                }
                _ => Err("JOIN takes channels, maybe keys, and maybe names"),
            }
        } else if cmd.eq_ignore_ascii_case("CAP") {
            let mut args = self.args_iter();
            let sub = args.next().ok_or("CAP requires sub-command")?;
            if sub.eq_ignore_ascii_case("LS") {
                Ok(Command::CapLs(args.next()))
            } else if sub.eq_ignore_ascii_case("END") {
                Ok(Command::CapEnd)
            } else {
                Ok(Command::CapUnknown)
            }
        } else {
            Ok(Command::Other(cmd))
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ShortArgs<'s> {
    Zero,
    One(&'s str),
    Two(&'s str, &'s str),
    Three(&'s str, &'s str, &'s str),
    Four(&'s str, &'s str, &'s str, &'s str),
    More,
}

impl<'i> Iterator for ParsedArgs<'i> {
    type Item = &'i str;

    fn next(&mut self) -> Option<&'i str> {
        // drop leading whitespace
        while self.buf[self.pos..].starts_with(' ') {
            self.pos += 1;
        }

        // if it's empty, we're done
        if self.buf[self.pos..].is_empty() {
            return None;
        }

        if self.buf[self.pos..].starts_with(':') {
            let rest = &self.buf[self.pos + 1..];
            self.pos = self.buf.len();
            return Some(rest);
        }

        let remaining = &self.buf[self.pos..];
        let len = remaining.find(' ').unwrap_or(remaining.len());
        self.pos += len;
        Some(&remaining[..len])
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::parse_message;
    use super::ShortArgs;

    fn assert_parses_to<S: ToString + fmt::Display>(
        expected: (Option<&str>, Option<&str>, &str, Option<&str>),
        input: S,
    ) {
        let m = parse_message(input.to_string().as_ref()).expect(&format!("parsing {}", input));
        let actual = (m.tags_str(), m.source_str(), m.cmd_str(), m.args_str());
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_commands() {
        assert_eq!(Err("empty command"), parse_message(""));
        assert_eq!(Err("only source"), parse_message(":woo"));
        assert_eq!(Err("only tags"), parse_message("@woo"));
        assert_eq!(Err("only source"), parse_message("@woo :woo"));
        assert_eq!(Err("empty command"), parse_message("@woo :woo "));
        assert_eq!(Err("empty command"), parse_message("@woo :woo  "));
        assert_eq!(Err("whitespace start"), parse_message(" "));

        assert_parses_to((None, None, "QUIT", None), "QUIT");
        assert_parses_to((None, Some("eye"), "QUIT", None), ":eye QUIT");
        assert_parses_to((None, Some("eye"), "QUIT", None), ":eye  QUIT");
        assert_parses_to((None, None, "GET", Some("/ HTTP/1.0")), "GET / HTTP/1.0");

        assert_parses_to(
            (Some("eye"), Some("eye"), "CAPTAIN", None),
            "@eye :eye CAPTAIN",
        );
    }

    #[test]
    fn parse_args() {
        let private = parse_message("PRIVMSG #woo :foo bar").unwrap();
        assert_eq!("PRIVMSG", private.cmd_str());
        assert_eq!(
            vec!["#woo", "foo bar"],
            private.args_iter().collect::<Vec<_>>()
        );
        assert_eq!(ShortArgs::Two("#woo", "foo bar"), private.args());

        let user = parse_message("USER foo bar 0 :Real Name").unwrap();
        assert_eq!("USER", user.cmd_str());
        assert_eq!(
            vec!["foo", "bar", "0", "Real Name"],
            user.args_iter().collect::<Vec<_>>()
        );
        assert_eq!(ShortArgs::Four("foo", "bar", "0", "Real Name"), user.args());

        let quit = parse_message("QUIT").unwrap();
        assert_eq!(Vec::<&str>::new(), quit.args_iter().collect::<Vec<_>>());
        assert_eq!(ShortArgs::Zero, quit.args());
    }
}
