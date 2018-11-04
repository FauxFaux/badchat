use std::ops::Range;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ParsedMessage<'b> {
    buf: &'b str,
    tags: Option<SubStr>,
    source: Option<SubStr>,
    cmd: SubStr,
    args: Option<SubStr>,
}

struct ParsedArgs<'b> {
    buf: &'b str,
    pos: usize,
}

// TODO: not sure it's clearer to have this not in terms of a generic
// TODO: iterator, which understands the two different :-prefixed arguments
fn parse_message(from: &str) -> Result<ParsedMessage, &'static str> {
    if from.starts_with(' ') {
        return Err("whitespace start");
    }

    // TODO: colours
    // Perfectly happy with this eliminating tab, etc.
    if from.contains(|c: char| c.is_ascii_control()) {
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

    if cmd.is_empty() {
        return Err("empty command");
    }

    Ok(ParsedMessage {
        buf: from,
        tags,
        source,
        cmd,
        args,
    })
}

impl<'b> ParsedMessage<'b> {
    fn tags_str(&self) -> Option<&str> {
        self.tags.map(|v| &self.buf[v.range()])
    }

    fn source_str(&self) -> Option<&str> {
        self.source.map(|v| &self.buf[v.range()])
    }

    fn cmd_str(&self) -> &str {
        &self.buf[self.cmd.range()]
    }

    fn args_str(&self) -> Option<&str> {
        self.args.map(|v| &self.buf[v.range()])
    }

    fn args(&self) -> ParsedArgs {
        ParsedArgs {
            buf: self.args_str().unwrap_or(""),
            pos: 0,
        }
    }
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

/// Range<> isn't Copy because it makes iterators *horrible*.
/// https://github.com/rust-lang/rust/pull/27186
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct SubStr {
    start: usize,
    end: usize,
}

impl SubStr {
    fn is_empty(self) -> bool {
        self.start >= self.end
    }

    #[inline]
    fn range(self) -> Range<usize> {
        Range {
            start: self.start,
            end: self.end,
        }
    }
}

impl Into<Range<usize>> for SubStr {
    fn into(self) -> Range<usize> {
        Range {
            start: self.start,
            end: self.end,
        }
    }
}

impl From<Range<usize>> for SubStr {
    fn from(them: Range<usize>) -> Self {
        SubStr {
            start: them.start,
            end: them.end,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_message;

    fn assert_parses_to(expected: (Option<&str>, Option<&str>, &str, Option<&str>), input: &str) {
        let m = parse_message(input).expect(&format!("parsing {}", input));
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
        assert_eq!(vec!["#woo", "foo bar"], private.args().collect::<Vec<_>>());

        let user = parse_message("USER foo bar 0 :Real Name").unwrap();
        assert_eq!("USER", user.cmd_str());
        assert_eq!(
            vec!["foo", "bar", "0", "Real Name"],
            user.args().collect::<Vec<_>>()
        );

        let quit = parse_message("QUIT").unwrap();
        assert_eq!(Vec::<&str>::new(), quit.args().collect::<Vec<_>>());
    }
}
