// SPDX-FileCopyrightText: (C) 2022 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Common helper parsers used by multiple keyword parsers.
use crate::{Base, Endian, NumberOrName, RuleParseError};
use nom::bytes::complete::{is_not, tag};
use nom::character::complete::multispace0;
use nom::sequence::preceded;
use nom::Err::Error;
use nom::IResult;
use num_traits::Num;
use std::str::FromStr;

/// Parse the next token ignoring leading whitespace.
///
/// A token is the next sequence of chars until a terminating character. Leading whitespace
/// is ignored.
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
    let (input, token) = parse_token(input)?;
    let number = if token.starts_with("0x") || token.starts_with("0X") {
        T::from_str_radix(&token[2..], 16)
            .map_err(|_| Error(RuleParseError::NumberParseError(token.to_string())))?
    } else {
        token
            .parse::<T>()
            .map_err(|_| Error(RuleParseError::NumberParseError(token.to_string())))?
    };
    Ok((input, number))
}

pub fn parse_number_or_name<T: FromStr + Num>(
    input: &str,
) -> IResult<&str, NumberOrName<T>, RuleParseError<&str>> {
    if let Ok((input, number)) = parse_number::<T>(input) {
        Ok((input, NumberOrName::Number(number)))
    } else {
        let (input, name) = parse_token(input)?;
        Ok((input, NumberOrName::Name(name.to_string())))
    }
}

pub fn parse_endian(input: &str) -> IResult<&str, Endian, RuleParseError<&str>> {
    let (input, endian) = parse_token(input)?;
    let endian = match endian {
        "big" => Endian::Big,
        "little" => Endian::Little,
        _ => {
            return Err(Error(RuleParseError::BadEndianValue(endian.to_string())));
        }
    };
    Ok((input, endian))
}

pub fn parse_base(input: &str) -> IResult<&str, Base, RuleParseError<&str>> {
    let (input, base) = parse_token(input)?;
    let base = match base {
        "dec" => Base::Dec,
        "hex" => Base::Hex,
        "oct" => Base::Oct,
        _ => {
            return Err(Error(RuleParseError::BadBase(base.to_string())));
        }
    };
    Ok((input, base))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_token() {
        assert_eq!(parse_token("foo"), Ok(("", "foo")));
        assert_eq!(parse_token("foo/bar"), Ok(("", "foo/bar")));
        assert_eq!(parse_token("foo, bar"), Ok((", bar", "foo")));
        assert_eq!(
            parse_token("1.1.1.1/32,2.2.2.2/0"),
            Ok((",2.2.2.2/0", "1.1.1.1/32"))
        );
    }
}
