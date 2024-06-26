// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    options::ByteJump,
    parsers::{parse_token, Endian},
};
use nom::bytes::complete::tag;
use nom::character::complete::multispace0;
use nom::sequence::preceded;
use nom::Err::Error;
use nom::IResult;

use super::{parse_number, parse_number_or_reference, parse_tag, ErrorKind, ParseError};

pub(crate) fn parse_byte_jump(input: &str) -> IResult<&str, ByteJump, ParseError<&str>> {
    let (input, byte_count) = parse_number::<usize>(input)?;
    let (input, _) = parse_tag(",")(input)?;
    let (input, offset) = parse_number_or_reference::<i32>(input)?;

    let mut byte_jump = ByteJump {
        count: byte_count,
        offset,
        ..Default::default()
    };

    if let Ok((input, _)) = parse_tag(",")(input) {
        // First separate the comma separated values.
        let (_, values) = nom::multi::separated_list1(
            tag(","),
            preceded(multispace0, nom::bytes::complete::is_not(",")),
        )(input)?;

        for value in values {
            let (value, name) = parse_token(value)?;
            match name {
                "relative" => {
                    byte_jump.relative = true;
                }
                "little" => {
                    byte_jump.endian = Endian::Little;
                }
                "big" => {
                    byte_jump.endian = Endian::Big;
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
                    let (_, multiplier) = parse_number(value)?;
                    byte_jump.multiplier = multiplier;
                }
                "post_offset" => {
                    let (_, post_offset) = parse_number(value)?;
                    byte_jump.post_offset = post_offset;
                }
                "bitmask" => {
                    let (_, bitmask) = parse_number(value)?;
                    byte_jump.bitmask = bitmask;
                }
                _ => {
                    return Err(Error(ParseError {
                        input: value,
                        kind: ErrorKind::Other("unknown_byte_jump_option"),
                    }));
                }
            }
        }
    }

    Ok((input, byte_jump))
}

#[cfg(test)]
mod test {
    use crate::parsers::NumberOrReference;

    use super::*;

    #[test]
    fn test_parse_byte_jump() {
        assert!(parse_byte_jump("4").is_err());
        assert!(parse_byte_jump("4,12").is_ok());

        let input = "4,12,relative,little,multiplier 2";
        let (_, byte_jump) = parse_byte_jump(input).unwrap();
        assert_eq!(byte_jump.count, 4);
        assert_eq!(byte_jump.offset, NumberOrReference::Number(12));
        assert!(byte_jump.relative);
        assert_eq!(byte_jump.endian, Endian::Little);
        assert_eq!(byte_jump.multiplier, 2);

        // Same as above but with a bitmask.
        let input = "4,12,relative,little,multiplier 2,bitmask 0x3c";
        let (_, byte_jump) = parse_byte_jump(input).unwrap();
        assert_eq!(byte_jump.bitmask, 0x3c);

        let input = "4,-18,relative,little,from_beginning, post_offset 1";
        let (_, _byte_jump) = parse_byte_jump(input).unwrap();
    }
}
