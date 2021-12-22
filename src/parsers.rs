// Copyright 2021 Jason Ish
//
// MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::types;
use crate::types::*;
use crate::RuleParseError;
use nom::branch::alt;
use nom::bytes::complete::{is_not, tag, take_until, take_while};
use nom::character::complete::{alphanumeric1, multispace0, multispace1};
use nom::combinator::{eof, opt, rest};
use nom::error::ErrorKind;
use nom::multi::separated_list0;
use nom::sequence::{preceded, terminated, tuple};
use nom::Err::Error;
use nom::IResult;
use std::str::FromStr;

static WHITESPACE: &str = " \t\r\n";

//
// Utility parsers.
//

/// Parse all characters up until the next whitespace character.
pub(crate) fn take_until_whitespace(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    nom::bytes::complete::is_not(WHITESPACE)(input)
}

pub(crate) fn parse_u64<'a>(
    input: &'a str,
    context: &str,
) -> IResult<&'a str, u64, RuleParseError<&'a str>> {
    let (_, input) = preceded(multispace0, take_until_whitespace)(input)?;
    let val = input.parse().map_err(|_| {
        nom::Err::Error(RuleParseError::IntegerParseError(format!(
            "{}: {}",
            context, input
        )))
    })?;
    Ok((input, val))
}

/// Parse a list like an address or port list.
///
/// This doesn't actually produce the elements of the list, but just the full string
/// encapsulating the list.
pub(crate) fn parse_list(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    let mut depth = 0;
    let mut end = 0;
    if input.is_empty() {
        return Err(nom::Err::Error(RuleParseError::Nom(input, ErrorKind::Eof)));
    }
    for (i, c) in input.chars().enumerate() {
        if i == 0 && c != '[' {
            // Cheat a little, just return the next non-whitespace token.
            return take_until_whitespace(input);
        }
        end = i;
        match c {
            '[' => {
                depth += 1;
            }
            ']' => {
                depth -= 1;
            }
            _ => {}
        }
        if depth == 0 {
            break;
        }
    }
    Ok((&input[end + 1..], &input[0..end + 1]))
}

//
// Element parsers.
//

pub(crate) fn parse_direction(
    input: &str,
) -> IResult<&str, types::Direction, RuleParseError<&str>> {
    let (input, direction) = alt((tag("->"), tag("<>")))(input)?;
    match direction {
        "->" => Ok((input, types::Direction::Single)),
        "<>" => Ok((input, types::Direction::Both)),
        _ => Err(nom::Err::Error(RuleParseError::InvalidDirection(
            direction.to_string(),
        ))),
    }
}

pub(crate) fn parse_count_or_name(
    input: &str,
) -> IResult<&str, types::CountOrName, RuleParseError<&str>> {
    let (_, input) = preceded(multispace0, take_until_whitespace)(input)?;
    if let Ok(distance) = input.parse() {
        Ok((input, types::CountOrName::Value(distance)))
    } else {
        Ok((input, types::CountOrName::Var(input.to_string())))
    }
}

pub(crate) fn parse_byte_jump(input: &str) -> IResult<&str, types::ByteJump, RuleParseError<&str>> {
    // First separate the comma separated values.
    let (_, values) = nom::multi::separated_list1(
        tag(","),
        preceded(multispace0, nom::bytes::complete::is_not(",")),
    )(input)?;
    if values.len() < 2 {
        return Err(Error(RuleParseError::InvalidByteJump(
            "not enough arguments".into(),
        )));
    }

    let mut byte_jump = types::ByteJump::default();

    // Inner utility function for easy error creation.
    fn make_error(reason: String) -> nom::Err<RuleParseError<&'static str>> {
        Error(RuleParseError::InvalidByteJump(reason))
    }

    byte_jump.count = values[0]
        .parse()
        .map_err(|_| make_error(format!("invalid count: {}", values[0])))?;

    byte_jump.offset = values[1]
        .parse()
        .map_err(|_| make_error(format!("invalid offset: {}", values[1])))?;

    for value in &values[2..] {
        let (value, name) = take_until_whitespace(value)?;
        match name {
            "relative" => {
                byte_jump.relative = true;
            }
            "little" => {
                byte_jump.endian = types::Endian::Little;
            }
            "big" => {
                byte_jump.endian = types::Endian::Big;
            }
            "align" => {
                byte_jump.align = true;
            }
            "from_beginning" => {
                byte_jump.from_beginning = true;
            }
            "from_end" => {
                byte_jump.from_end = true;
            }
            "dce" => {
                byte_jump.dce = true;
            }
            "string" => {
                byte_jump.string = true;
            }
            "hex" => {
                byte_jump.hex = true;
            }
            "dec" => {
                byte_jump.dec = true;
            }
            "oct" => {
                byte_jump.oct = true;
            }
            "multiplier" => {
                byte_jump.multiplier = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| make_error(format!("invalid multiplier: {}", value)))?;
            }
            "post_offset" => {
                byte_jump.post_offset = value
                    .trim()
                    .parse::<i64>()
                    .map_err(|_| make_error(format!("invalid post_offset: {}", value)))?;
            }
            "bitmask" => {
                let value = value.trim();
                let trimmed = if value.starts_with("0x") || value.starts_with("0X") {
                    &value[2..]
                } else {
                    value
                };
                let value = u64::from_str_radix(trimmed, 16)
                    .map_err(|_| make_error(format!("invalid bitmask: {}", value)))?;
                byte_jump.bitmask = value;
            }
            _ => {
                return Err(make_error(format!("unknown parameter: {}", name)));
            }
        }
    }

    Ok((input, byte_jump))
}

pub(crate) fn parse_flowbits(input: &str) -> IResult<&str, Flowbits, RuleParseError<&str>> {
    let command_parser = preceded(multispace0, alphanumeric1);
    let name_parser = preceded(tag(","), preceded(multispace0, rest));
    let (input, (command, names)) = tuple((command_parser, opt(name_parser)))(input)?;
    let command = FlowbitCommand::from_str(command)?;

    fn make_error<S: AsRef<str>>(reason: S) -> nom::Err<RuleParseError<&'static str>> {
        Error(RuleParseError::Flowbit(reason.as_ref().to_string()))
    }

    match command {
        FlowbitCommand::IsNotSet
        | FlowbitCommand::Unset
        | FlowbitCommand::Toggle
        | FlowbitCommand::IsSet
        | FlowbitCommand::Set => {
            let names = names
                .ok_or_else(|| make_error(format!("{} requires argument", command)))?
                .split('|')
                .map(|s| s.trim().to_string())
                .collect();
            Ok((input, Flowbits { command, names }))
        }
        FlowbitCommand::NoAlert => {
            if names.is_some() {
                Err(make_error("noalert takes no arguments"))
            } else {
                Ok((
                    input,
                    Flowbits {
                        command,
                        names: vec![],
                    },
                ))
            }
        }
    }
}

pub(crate) fn parse_xbits(input: &str) -> IResult<&str, XBits, RuleParseError<&str>> {
    let (input, command) = preceded(multispace0, alphanumeric1)(input)?;
    let command = XbitCommand::from_str(command)?;
    let (input, _) = preceded(multispace0, tag(","))(input)?;
    let (input, name) = preceded(multispace0, is_not(","))(input)?;
    let (input, _) = preceded(multispace0, tag(","))(input)?;
    let track_parser = preceded(multispace0, tuple((tag("track"), multispace0, is_not(","))));
    let (input, (_, _, track)) = preceded(multispace0, track_parser)(input)?;

    fn parse_expire(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
        let (input, _) = preceded(multispace0, tag(","))(input)?;
        let (input, _) = multispace0(input)?;
        let (input, _) = tag("expire")(input)?;
        let (input, _) = multispace1(input)?;
        let (input, expires) = alphanumeric1(input)?;
        Ok((input, expires))
    }

    let end = preceded(multispace0, alt((eof, tag(";"))));
    let (input, expire) = alt((parse_expire, end))(input)?;
    let expire = if expire.is_empty() {
        None
    } else {
        let expire: u64 = expire
            .parse()
            .map_err(|_| Error(RuleParseError::Other("invalid expire".to_string())))?;
        Some(expire)
    };
    let (input, _) = preceded(multispace0, alt((eof, tag(";"))))(input)?;

    Ok((
        input,
        XBits {
            command,
            name: name.trim().to_string(),
            track: track.trim().to_string(),
            expire,
        },
    ))
}

pub(crate) fn parse_flow(input: &str) -> IResult<&str, Vec<Flow>, RuleParseError<&str>> {
    let (input, values) = separated_list0(tag(","), preceded(multispace0, is_not(",")))(input)?;
    let mut options = vec![];
    for option in values {
        options.push(Flow::from_str(option.trim())?);
    }
    Ok((input, options))
}

/// Parse the metadata into a list of the comma separated values.
pub(crate) fn parse_metadata(input: &str) -> IResult<&str, Vec<String>, RuleParseError<&str>> {
    let sep = terminated(multispace0, preceded(multispace0, tag(",")));
    let (input, parts) = separated_list0(
        sep,
        preceded(multispace0, take_while(|c| c != ',' && c != ';')),
    )(input)?;
    let parts: Vec<String> = parts.iter().map(|p| p.trim().to_string()).collect();
    Ok((input, parts))
}

pub(crate) fn parse_pcre(input: &str) -> IResult<&str, Pcre, RuleParseError<&str>> {
    let (input, negate) = opt(tag("!"))(input)?;
    let (input, _open_quote) = tag("\"")(input)?;
    let (input, _open_pcre) = tag("/")(input)?;
    let pattern_end = input.rfind('/').ok_or_else(|| {
        nom::Err::Error(RuleParseError::Other("pcre: no terminating /".to_string()))
    })?;
    let pattern = &input[0..pattern_end];
    let input = &input[pattern_end..];
    let (input, _close_re) = tag("/")(input)?;

    // Return what we have if we're at the end of the quoted section.
    if let Ok((input, _)) = parse_end_quote(input) {
        let pcre = Pcre {
            negate: negate.is_some(),
            pattern: pattern.to_string(),
            modifiers: "".to_string(),
            vars: vec![],
        };
        return Ok((input, pcre));
    }

    // Now parse the modifiers.
    let (input, modifiers) = alphanumeric1(input)?;

    // There might also be some variable captures.
    let parse_start_of_vars = preceded(multispace0, tag(","));
    let parse_vars = preceded(parse_start_of_vars, take_until("\""));
    let (input, vars) = opt(parse_vars)(input)?;
    let (input, _) = parse_end_quote(input)?;

    let vars: Vec<String> = if let Some(vars) = vars {
        vars.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        vec![]
    };

    let pcre = Pcre {
        negate: negate.is_some(),
        pattern: pattern.to_string(),
        modifiers: modifiers.to_string(),
        vars,
    };
    Ok((input, pcre))
}

/// Parse an end quote. Probably not the best name for thie parser but it parses up to and
/// including a quote that is only prefixed by optional whitespace.
fn parse_end_quote(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    preceded(multispace0, tag("\""))(input)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_pcre() {
        let input0 = r#""/[0-9]{6}/""#;
        let (rem, pcre) = parse_pcre(input0).unwrap();
        assert_eq!(rem, "");
        assert_eq!(
            pcre,
            Pcre {
                negate: false,
                pattern: r#"[0-9]{6}"#.to_string(),
                modifiers: "".to_string(),
                vars: vec![],
            }
        );

        let input0 = r#""/[0-9]{6}/UR""#;
        let (rem, pcre) = parse_pcre(input0).unwrap();
        assert_eq!(rem, "");
        assert_eq!(
            pcre,
            Pcre {
                negate: false,
                pattern: r#"[0-9]{6}"#.to_string(),
                modifiers: "UR".to_string(),
                vars: vec![],
            }
        );

        let input0 = "\"/([^:/$]+)/R,flow:rce_server\"";
        let (_, pcre) = parse_pcre(input0).unwrap();
        assert_eq!(
            pcre,
            Pcre {
                negate: false,
                pattern: r#"([^:/$]+)"#.to_string(),
                modifiers: "R".to_string(),
                vars: vec!["flow:rce_server".to_string()],
            }
        );

        let input0 = "\"/([^:/$]+)/Ri, flow:rce_server\"";
        let (_, pcre) = parse_pcre(input0).unwrap();
        assert_eq!(
            pcre,
            Pcre {
                negate: false,
                pattern: r#"([^:/$]+)"#.to_string(),
                modifiers: "Ri".to_string(),
                vars: vec!["flow:rce_server".to_string()],
            }
        );

        let input0 = r#""/\/winhost(?:32|64)\.(exe|pack)$/i""#;
        let (_, pcre) = parse_pcre(input0).unwrap();
        assert_eq!(
            pcre,
            Pcre {
                negate: false,
                pattern: r#"\/winhost(?:32|64)\.(exe|pack)$"#.to_string(),
                modifiers: "i".to_string(),
                vars: vec![],
            }
        );

        let input0 = r#""/\/(?=[0-9]*?[a-z]*?[a-z0-9)(?=[a-z0-9]*[0-9][a-z]*[0-9][a-z0-9]*\.exe)(?!setup\d+\.exe)[a-z0-9]{5,15}\.exe/""#;
        let (_, _pcre) = parse_pcre(input0).unwrap();

        let input0 = r#""/passwd/main\x2Ephp\x3F[^\x0A\x0D]*backend\x3D[^\x0A\x0D\x26]*\x22/i""#;
        let (_, _pcre) = parse_pcre(input0).unwrap();

        let input0 = r#""/^(?:d(?:(?:ocu|uco)sign|ropbox)|o(?:ffice365|nedrive)|adobe|gdoc)/""#;
        let (_, _pcre) = parse_pcre(input0).unwrap();

        let input0 = r#"!"/^onedrivecl[a-z]{2}prod[a-z]{2}[0-9]{5}\./""#;
        let (_, pcre) = parse_pcre(input0).unwrap();
        assert_eq!(rem, "");
        assert_eq!(pcre.negate, true);
    }

    #[test]
    fn test_parse_metadata() {
        let (_, metadata) = parse_metadata("oneword").unwrap();
        assert_eq!(&metadata, &["oneword"]);

        let (_, metadata) = parse_metadata("one,two").unwrap();
        assert_eq!(&metadata, &["one", "two"]);

        let (_, metadata) = parse_metadata("one ,two").unwrap();
        assert_eq!(&metadata, &["one", "two"]);

        let (_, metadata) = parse_metadata("one , two").unwrap();
        assert_eq!(&metadata, &["one", "two"]);

        let (_, metadata) = parse_metadata("key val , key val").unwrap();
        assert_eq!(&metadata, &["key val", "key val"]);

        let (rem, metadata) = parse_metadata("key val , key val;").unwrap();
        assert_eq!(&metadata, &["key val", "key val"]);
        assert_eq!(rem, ";");
    }

    #[test]
    fn test_parse_flow() {
        let flow = parse_flow("to_client,established").unwrap();
        assert_eq!(flow.1, vec![Flow::ToClient, Flow::Established]);

        let flow = parse_flow("to_client, established").unwrap();
        assert_eq!(flow.1, vec![Flow::ToClient, Flow::Established]);

        let flow = parse_flow("to_client").unwrap();
        assert_eq!(flow.1, vec![Flow::ToClient]);

        let flow = parse_flow(" to_client").unwrap();
        assert_eq!(flow.1, vec![Flow::ToClient]);

        let flow = parse_flow(" to_client  ,    established   ").unwrap();
        assert_eq!(flow.1, vec![Flow::ToClient, Flow::Established]);
    }

    #[test]
    fn test_parse_xbits() {
        let (_, xbits) = parse_xbits("set,ET.dropsite,track ip_src").unwrap();
        assert_eq!(
            xbits,
            XBits {
                command: XbitCommand::Set,
                name: "ET.dropsite".to_string(),
                track: "ip_src".to_string(),
                expire: None,
            }
        );

        let (_, xbits) = parse_xbits("set  ,  ET.dropsite  ,  track ip_src").unwrap();
        assert_eq!(
            xbits,
            XBits {
                command: XbitCommand::Set,
                name: "ET.dropsite".to_string(),
                track: "ip_src".to_string(),
                expire: None,
            }
        );

        let (_, xbits) = parse_xbits("set,ET.dropsite,track ip_src,expire 5000").unwrap();
        assert_eq!(
            xbits,
            XBits {
                command: XbitCommand::Set,
                name: "ET.dropsite".to_string(),
                track: "ip_src".to_string(),
                expire: Some(5000),
            }
        );

        let (_, xbits) = parse_xbits("set,ET.dropsite,track ip_src  , expire 5000  ").unwrap();
        assert_eq!(
            xbits,
            XBits {
                command: XbitCommand::Set,
                name: "ET.dropsite".to_string(),
                track: "ip_src".to_string(),
                expire: Some(5000),
            }
        );

        assert!(parse_xbits("set,ET.dropsite,track ip_src,a").is_err());
        assert!(parse_xbits("set,ET.dropsite,track ip_src, expire a").is_err());
        assert!(parse_xbits("set,ET.dropsite,track ip_src, expire 5000 a").is_err());
    }
}
