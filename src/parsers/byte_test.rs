// SPDX-License-Identifier: MIT
//
// Copyright (C) 2022 Jason Ish

use crate::common::{
    parse_base, parse_endian, parse_number, parse_number_or_name, parse_tag, parse_token,
};
use crate::{Base, ByteTest, ByteTestOperator, Endian, RuleParseError};
use nom::Err::Error;
use nom::IResult;

fn parse_op(input: &str) -> IResult<&str, ByteTestOperator, RuleParseError<&str>> {
    let (input, op) = parse_token(input)?;
    let op = match op {
        "<" => ByteTestOperator::Lt,
        ">" => ByteTestOperator::Gt,
        "<=" => ByteTestOperator::Lte,
        ">=" => ByteTestOperator::Gte,
        "=" => ByteTestOperator::Eq,
        "&" => ByteTestOperator::And,
        "^" => ByteTestOperator::Or,
        _ => {
            return Err(nom::Err::Error(RuleParseError::Other(format!(
                "invalid byte test operator: {}",
                op
            ))));
        }
    };
    Ok((input, op))
}

pub fn parse_byte_test(input: &str) -> IResult<&str, ByteTest, RuleParseError<&str>> {
    let (input, bytes) = parse_number::<usize>(input)?;
    let (input, _) = parse_tag(",")(input)?;
    let (input, op) = parse_op(input)?;
    let (input, _) = parse_tag(",")(input)?;
    let (input, value) = parse_number_or_name::<u64>(input)?;
    let (input, _) = parse_tag(",")(input)?;
    let (input, offset) = parse_number_or_name::<i32>(input)?;

    let mut relative = false;
    let mut endian = Endian::Big;
    let mut string = false;
    let mut base = Base::default();
    let mut dce = false;
    let mut bitmask = 0;

    let mut input = input;
    while let Ok((i, _)) = parse_tag(",")(input) {
        let (mut i, opt) = parse_token(i)?;
        match opt {
            "relative" => relative = true,
            "endian" => {
                let (_i, _endian) = parse_endian(i)?;
                i = _i;
                endian = _endian;
            }
            "dce" => dce = true,
            "bitmask" => {
                let (_i, _bitmask) = parse_number(i)?;
                i = _i;
                bitmask = _bitmask;
            }
            "string" => {
                string = true;
                let (_i, _) = parse_tag(",")(i)?;
                let (_i, _base) = parse_base(_i)?;
                base = _base;
                i = _i;
            }
            _ => {
                return Err(Error(RuleParseError::UnknownOption(opt.to_string())));
            }
        }
        input = i;
    }

    Ok((
        input,
        ByteTest {
            bytes,
            op,
            value,
            offset,
            relative,
            endian,
            string,
            base,
            dce,
            bitmask,
        },
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::NumberOrName;

    #[test]
    fn test_parse_byte_test() {
        parse_byte_test("1,=,1,OFFSET,relative").unwrap();
        parse_byte_test("2,=,1,1").unwrap();
        parse_byte_test("2,=,1,0x1").unwrap();

        let (_, bt) = parse_byte_test("4,=,1337,1,relative,string,dec").unwrap();
        assert_eq!(
            bt,
            ByteTest {
                bytes: 4,
                op: ByteTestOperator::Eq,
                value: NumberOrName::Number(1337),
                offset: NumberOrName::Number(1),
                relative: true,
                endian: Endian::Big,
                string: true,
                base: Base::Dec,
                dce: false,
                bitmask: 0,
            }
        );

        let (_, bt) = parse_byte_test("8, =, 0xdeadbeef, 0, string, hex").unwrap();
        assert_eq!(
            bt,
            ByteTest {
                bytes: 8,
                op: ByteTestOperator::Eq,
                value: NumberOrName::Number(0xdeadbeef),
                offset: NumberOrName::Number(0),
                relative: false,
                endian: Endian::Big,
                string: true,
                base: Base::Hex,
                dce: false,
                bitmask: 0,
            }
        );
    }
}
