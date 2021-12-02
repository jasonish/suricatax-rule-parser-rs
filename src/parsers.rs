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
use nom::bytes::complete::{is_not, tag};
use nom::character::complete::{alphanumeric1, multispace0};
use nom::combinator::{opt, rest};
use nom::error::ErrorKind;
use nom::multi::separated_list0;
use nom::sequence::{preceded, tuple};
use nom::Err::Error;
use nom::IResult;
use std::str::FromStr;

static WHITESPACE: &str = " \t\r\n";

//
// Utility parsers.
///

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

pub(crate) fn parse_flow(input: &str) -> IResult<&str, Vec<Flow>, RuleParseError<&str>> {
    let (input, values) = separated_list0(tag(","), preceded(multispace0, is_not(",")))(input)?;
    let mut options = vec![];
    for option in values {
        options.push(Flow::from_str(option.trim())?);
    }
    Ok((input, options))
}

#[cfg(test)]
mod test {
    use super::*;

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
}
