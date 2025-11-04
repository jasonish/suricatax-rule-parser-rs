// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rule scanner for tokenizing Suricata rules.
//!
//! This module provides a streaming scanner that breaks rules into their
//! component parts without attempting to parse option values in detail.

use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::multispace0,
    sequence::preceded,
    IResult,
};
use serde::Serialize;

use crate::{types::Direction, Error};

static WHITESPACE: &str = " \t\r\n";

/// Events emitted by the rule scanner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleScanEvent {
    Action(String),
    Protocol(String),
    SourceIp(String),
    SourcePort(String),
    Direction(String),
    DestIp(String),
    DestPort(String),
    StartOfOptions(String),
    Option { name: String, value: Option<String> },
    EndOfOptions(String),
}

/// A streaming scanner for Suricata rules.
///
/// The scanner implements `Iterator` and yields `RuleScanEvent` items that
/// represent the tokenized components of a rule.
pub struct RuleScanner<'a> {
    state: ScannerState,
    buf: &'a str,
    next: &'a str,
    done: bool,
}

impl<'a> RuleScanner<'a> {
    /// Create a new scanner for the given rule string.
    pub fn new(buf: &'a str) -> Self {
        Self {
            state: ScannerState::Action,
            buf,
            next: buf,
            done: false,
        }
    }
}

impl<'a> Iterator for RuleScanner<'a> {
    type Item = Result<RuleScanEvent, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.state {
            ScannerState::Action => match take_until_whitespace(self.next) {
                Ok((next, action)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::Action(action.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "action"))),
            },
            ScannerState::Protocol => match take_until_whitespace(self.next) {
                Ok((next, proto)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::Protocol(proto.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "protocol"))),
            },
            ScannerState::SourceIp => match scan_array(self.next) {
                Ok((next, src_ip)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::SourceIp(src_ip.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "source-ip"))),
            },
            ScannerState::SourcePort => match scan_array(self.next) {
                Ok((next, value)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::SourcePort(value.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "source-port"))),
            },
            ScannerState::Direction => {
                match preceded(multispace0, parse_direction)(self.next) {
                    Ok((next, direction)) => {
                        self.state = self.state.next();
                        self.next = next;
                        Some(Ok(RuleScanEvent::Direction(direction.to_string())))
                    }
                    Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "direction"))),
                }
            }
            ScannerState::DestIp => match scan_array(self.next) {
                Ok((next, v)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::DestIp(v.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "destination-ip"))),
            },
            ScannerState::DestPort => match scan_array(self.next) {
                Ok((next, v)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::DestPort(v.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(
                    err,
                    self.buf,
                    "destination-port",
                ))),
            },
            ScannerState::StartOfOptions => match start_of_options(self.next) {
                Ok((next, value)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::StartOfOptions(value.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(
                    err,
                    self.buf,
                    "start of options",
                ))),
            },
            ScannerState::Options => {
                if let Ok((next, v)) = end_of_options(self.next) {
                    self.next = next;
                    self.done = true;
                    return Some(Ok(RuleScanEvent::EndOfOptions(v.to_string())));
                }
                let name = match option_name(self.next) {
                    Ok((rem, name)) => {
                        self.next = rem;
                        name
                    }
                    Err(err) => {
                        return Some(Err(Error::from_nom_error(err, self.buf, "option name")));
                    }
                };
                let sep = match options_separator(self.next) {
                    Ok((rem, sep)) => {
                        self.next = rem;
                        sep
                    }
                    Err(err) => {
                        return Some(Err(Error::from_nom_error(
                            err,
                            self.buf,
                            "option separator",
                        )));
                    }
                };
                if sep == ':' {
                    let value = match parse_option_value(self.next) {
                        Ok((rem, value)) => {
                            self.next = rem;
                            value
                        }
                        Err(err) => {
                            return Some(Err(Error::from_nom_error(err, self.buf, "option value")));
                        }
                    };
                    Some(Ok(RuleScanEvent::Option {
                        name: name.to_string(),
                        value: Some(value.to_string()),
                    }))
                } else {
                    Some(Ok(RuleScanEvent::Option {
                        name: name.to_string(),
                        value: None,
                    }))
                }
            }
        }
    }
}

/// Internal state machine for scanning.
#[derive(Debug, PartialEq, Eq)]
enum ScannerState {
    Action,
    Protocol,
    SourceIp,
    SourcePort,
    Direction,
    DestIp,
    DestPort,
    StartOfOptions,
    Options,
}

impl ScannerState {
    fn next(&self) -> Self {
        match self {
            ScannerState::Action => ScannerState::Protocol,
            ScannerState::Protocol => ScannerState::SourceIp,
            ScannerState::SourceIp => ScannerState::SourcePort,
            ScannerState::SourcePort => ScannerState::Direction,
            ScannerState::Direction => ScannerState::DestIp,
            ScannerState::DestIp => ScannerState::DestPort,
            ScannerState::DestPort => ScannerState::StartOfOptions,
            ScannerState::StartOfOptions => ScannerState::Options,
            ScannerState::Options => ScannerState::Options,
        }
    }
}

/// Scanner error type (crate-internal).
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ScanError<I> {
    pub reason: String,
    pub input: I,
}

impl<'a> From<nom::Err<ScanError<&'a str>>> for ScanError<&'a str> {
    fn from(err: nom::Err<ScanError<&'a str>>) -> Self {
        match err {
            nom::Err::Error(err) => err,
            nom::Err::Failure(err) => err,
            nom::Err::Incomplete(_) => unreachable!(),
        }
    }
}

impl<I> nom::error::ParseError<I> for ScanError<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self {
            reason: format!("nom error: {}", kind.description()),
            input,
        }
    }

    fn append(_: I, _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

/// Get the next sequence of characters up until the next whitespace,
/// ignoring any leading whitespace.
fn take_until_whitespace(input: &str) -> IResult<&str, &str, ScanError<&str>> {
    preceded(multispace0, is_not(WHITESPACE))(input)
}

/// Scan an array returning a String of the array contents.
fn scan_array(input: &str) -> IResult<&str, &str, ScanError<&str>> {
    let input = input.trim_start();

    // We might not always have an array, if not, parse a scalar.
    if !input.starts_with('[') {
        let (input, scalar) = preceded(multispace0, is_not("\n\r\t "))(input)?;
        return Ok((input, scalar));
    }

    let mut depth = 0;
    let mut offset = 0;

    for c in input.chars() {
        offset += c.len_utf8();
        match c {
            '[' => {
                depth += 1;
            }
            ']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }

    Ok((&input[offset..], &input[0..offset]))
}

/// Parse the value for an option.
///
/// This parser expects the input to be the first character after the ':'
/// following an option name. It will return all the characters up to but not
/// including the option terminator ';', handling all escaped occurrences of the
/// option terminator.
///
/// The remaining input returned does not contain the option terminator.
fn parse_option_value(input: &str) -> IResult<&str, &str, ScanError<&str>> {
    let mut escaped = false;
    let mut end = 0;
    let mut terminated = false;

    // First jump over any leading whitespace.
    let (input, _) = multispace0(input)?;

    for c in input.chars() {
        end += c.len_utf8();
        if c == '\\' {
            escaped = true;
        } else if escaped {
            escaped = false;
        } else if c == ';' {
            terminated = true;
            break;
        }
    }

    if !terminated {
        Err(nom::Err::Error(ScanError {
            reason: "unterminated rule option value".to_string(),
            input,
        }))
    } else {
        Ok((&input[(end - 1) + 1..], &input[0..(end - 1)]))
    }
}

fn start_of_options(input: &str) -> IResult<&str, &str, ScanError<&str>> {
    preceded(multispace0, tag("("))(input)
}

fn end_of_options(input: &str) -> IResult<&str, &str> {
    preceded(multispace0, tag(")"))(input)
}

fn option_name(input: &str) -> IResult<&str, &str, ScanError<&str>> {
    preceded(multispace0, is_not(";:"))(input)
}

fn options_separator(input: &str) -> IResult<&str, char, ScanError<&str>> {
    preceded(multispace0, nom::character::complete::one_of(";:"))(input)
}

fn parse_direction(input: &str) -> IResult<&str, Direction, ScanError<&str>> {
    let parse_single = |input| -> IResult<&str, Direction, ScanError<&str>> {
        let (input, _) = tag("->")(input)?;
        Ok((input, Direction::Single))
    };

    let parse_both = |input| -> IResult<&str, Direction, ScanError<&str>> {
        let (input, _) = tag("<>")(input)?;
        Ok((input, Direction::Both))
    };

    let (rem, direction) = alt((parse_single, parse_both))(input).map_err(|_| {
        nom::Err::Error(ScanError {
            reason: "invalid direction".to_string(),
            input,
        })
    })?;
    Ok((rem, direction))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rule_scanner() {
        let input =
            r#"alert tcp any any -> any any (msg:"TEST"; content:"|aa bb cc dd|"; nocase; sid:1;)"#;

        let mut scanner = RuleScanner::new(input);

        let action = scanner.next().unwrap().unwrap();
        assert_eq!(action, RuleScanEvent::Action("alert".to_string()));

        let proto = scanner.next().unwrap().unwrap();
        assert_eq!(proto, RuleScanEvent::Protocol("tcp".to_string()));

        let src_ip = scanner.next().unwrap().unwrap();
        assert_eq!(src_ip, RuleScanEvent::SourceIp("any".to_string()));

        let src_port = scanner.next().unwrap().unwrap();
        assert_eq!(src_port, RuleScanEvent::SourcePort("any".to_string()));

        let direction = scanner.next().unwrap().unwrap();
        assert_eq!(direction, RuleScanEvent::Direction("->".to_string()));

        let dest_ip = scanner.next().unwrap().unwrap();
        assert_eq!(dest_ip, RuleScanEvent::DestIp("any".to_string()));

        let dest_port = scanner.next().unwrap().unwrap();
        assert_eq!(dest_port, RuleScanEvent::DestPort("any".to_string()));

        let start_of_options = scanner.next().unwrap().unwrap();
        assert_eq!(
            start_of_options,
            RuleScanEvent::StartOfOptions("(".to_string())
        );

        let option = scanner.next().unwrap().unwrap();
        assert_eq!(
            option,
            RuleScanEvent::Option {
                name: "msg".to_string(),
                value: Some("\"TEST\"".to_string())
            }
        );

        let option = scanner.next().unwrap().unwrap();
        assert_eq!(
            option,
            RuleScanEvent::Option {
                name: "content".to_string(),
                value: Some("\"|aa bb cc dd|\"".to_string())
            }
        );

        let option = scanner.next().unwrap().unwrap();
        assert_eq!(
            option,
            RuleScanEvent::Option {
                name: "nocase".to_string(),
                value: None
            }
        );

        let option = scanner.next().unwrap().unwrap();
        assert_eq!(
            option,
            RuleScanEvent::Option {
                name: "sid".to_string(),
                value: Some("1".to_string())
            }
        );

        let event = scanner.next().unwrap().unwrap();
        assert_eq!(event, RuleScanEvent::EndOfOptions(")".to_string()));

        let event = scanner.next();
        assert_eq!(event, None);
    }
}
