// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core parsers for basic types used by the rule scanner.

use std::fmt;

use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::multispace0,
    sequence::preceded,
    IResult,
};

use crate::types::*;


static WHITESPACE: &str = " \t\r\n";

// Parser error types

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum ErrorKind {
    UnterminatedRuleOptionValue,
    Invalid,
    Nom(nom::error::ErrorKind),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ErrorKind::UnterminatedRuleOptionValue => write!(f, "unterminated rule option value"),
            ErrorKind::Invalid => write!(f, "invalid"),
            ErrorKind::Nom(kind) => write!(f, "nom error: {}", kind.description()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ParseError<I> {
    pub kind: ErrorKind,
    pub input: I,
}

/// Converts a nom error into a ParseError.
///
/// Allows parsers to return a normal Result when not used as part of
/// a combinator.
impl<'a> From<nom::Err<ParseError<&'a str>>> for ParseError<&'a str> {
    fn from(err: nom::Err<ParseError<&'a str>>) -> Self {
        match err {
            nom::Err::Error(err) => err,
            nom::Err::Failure(err) => err,
            nom::Err::Incomplete(_) => unreachable!(),
        }
    }
}

impl<I> nom::error::ParseError<I> for ParseError<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self {
            kind: ErrorKind::Nom(kind),
            input,
        }
    }

    fn append(_: I, _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

/// Get the next sequence of characters up until the next whitespace,
/// ignoring any leading whitespace.
pub(crate) fn take_until_whitespace(input: &str) -> IResult<&str, &str, ParseError<&str>> {
    preceded(multispace0, is_not(WHITESPACE))(input)
}

/// Scan an array returning a String of the array contents.
pub(crate) fn scan_array(input: &str) -> IResult<&str, &str, ParseError<&str>> {
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
pub(crate) fn parse_option_value(input: &str) -> IResult<&str, &str, ParseError<&str>> {
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
        Err(nom::Err::Error(ParseError {
            kind: ErrorKind::UnterminatedRuleOptionValue,
            input,
        }))
    } else {
        Ok((&input[(end - 1) + 1..], &input[0..(end - 1)]))
    }
}

pub(crate) fn start_of_options(input: &str) -> IResult<&str, &str, ParseError<&str>> {
    preceded(multispace0, tag("("))(input)
}

pub(crate) fn end_of_options(input: &str) -> IResult<&str, &str> {
    preceded(multispace0, tag(")"))(input)
}

pub(crate) fn option_name(input: &str) -> IResult<&str, &str, ParseError<&str>> {
    preceded(multispace0, nom::bytes::complete::is_not(";:"))(input)
}

pub(crate) fn options_separator(input: &str) -> IResult<&str, char, ParseError<&str>> {
    preceded(multispace0, nom::character::complete::one_of(";:"))(input)
}

pub(crate) fn parse_direction(input: &str) -> IResult<&str, Direction, ParseError<&str>> {
    let parse_single = |input| -> IResult<&str, Direction, ParseError<&str>> {
        let (input, _) = tag("->")(input)?;
        Ok((input, Direction::Single))
    };

    let parse_both = |input| -> IResult<&str, Direction, ParseError<&str>> {
        let (input, _) = tag("<>")(input)?;
        Ok((input, Direction::Both))
    };

    let (rem, direction) = alt((parse_single, parse_both))(input).map_err(|_| {
        nom::Err::Error(ParseError {
            kind: ErrorKind::Invalid,
            input,
        })
    })?;
    Ok((rem, direction))
}
