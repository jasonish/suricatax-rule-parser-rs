// SPDX-License-Identifier: MIT
//
// Copyright (C) 2022 Open Information Security Foundation

/// Common helper parsers used by multiple keyword parsers.
use crate::RuleParseError;
use nom::bytes::complete::{is_not, tag};
use nom::character::complete::multispace0;
use nom::combinator::map_res;
use nom::sequence::preceded;
use nom::IResult;
use num_traits::Num;
use std::str::FromStr;

/// Parse the next token ignoring leading whitespace.
///
/// A token is the next sequence of chars until a terminating character. Leading whitespace
/// is ignore.
pub fn parse_token(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    let terminators = "\n\r\t,;: ";
    preceded(multispace0, is_not(terminators))(input)
}

/// Parse a tag ignoring any leading whitespace.
///
/// Useful for parsing an expected separator or keyword.
pub fn parse_tag(sep: &str) -> impl Fn(&str) -> IResult<&str, &str, RuleParseError<&str>> + '_ {
    move |input| preceded(multispace0, tag(sep))(input)
}

/// Parser a number of type T.
pub fn parse_number<T: FromStr + Num>(input: &str) -> IResult<&str, T, RuleParseError<&str>> {
    map_res(parse_token, |s: &str| s.parse::<T>())(input)
}
