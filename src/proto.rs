use std::ops::Range;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ParsedMessage<'b> {
    buf: &'b str,
    tags: Option<SubStr>,
    source: Option<SubStr>,
    cmd: SubStr,
    args: Option<SubStr>,
}

fn parse_message(from: &str) -> Result<ParsedMessage, &'static str> {
    if from.starts_with(' ') {
        return Err("whitespace start");
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
    fn parse() {
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
}
