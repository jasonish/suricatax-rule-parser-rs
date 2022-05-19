// SPDX-License-Identifier: MIT
//
// Copyright (C) 2022 Open Information Security Foundation

use crate::common::{parse_number, parse_tag, parse_token};
use crate::RuleParseError;
use nom::Err::Error;
use nom::IResult;
use serde::Deserialize;
use serde::Serialize;
use std::convert::TryFrom;

#[cfg_attr(
    feature = "serde_support",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Debug, PartialEq, Clone)]
pub struct ByteMath {
    bytes: i64,
    offset: i64,
    oper: ByteMathOperator,
    rvalue: Rvalue,
    result: String,
    relative: bool,
    endian: Endian,
    base: Base,
    dce: bool,
    bitmask: u32,
}

#[cfg_attr(
    feature = "serde_support",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Debug, PartialEq, Clone)]
pub enum ByteMathOperator {
    Add,
    Sub,
    Mul,
    Div,
    Lshift,
    Rshift,
}

impl<'a> TryFrom<&'a str> for ByteMathOperator {
    type Error = RuleParseError<&'a str>;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let op = match value {
            "+" => Self::Add,
            "-" => Self::Sub,
            "*" => Self::Mul,
            "/" => Self::Div,
            "<<" => Self::Lshift,
            ">>" => Self::Rshift,
            _ => {
                return Err(RuleParseError::BadByteMathOperator(value.to_string()));
            }
        };
        Ok(op)
    }
}

#[cfg_attr(
    feature = "serde_support",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Debug, Clone, PartialEq)]
pub enum Endian {
    Big,
    Little,
}

impl Default for Endian {
    fn default() -> Self {
        Self::Big
    }
}

impl<'a> TryFrom<&'a str> for Endian {
    type Error = RuleParseError<&'a str>;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let endian = match value {
            "big" => Self::Big,
            "little" => Self::Little,
            _ => {
                return Err(RuleParseError::BadEndianValue(value.to_string()));
            }
        };
        Ok(endian)
    }
}

#[cfg_attr(
    feature = "serde_support",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Debug, Clone, PartialEq)]
pub enum Rvalue {
    Value(i64),
    Name(String),
}

#[cfg_attr(
    feature = "serde_support",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Debug, Clone, PartialEq)]
pub enum Base {
    Dec,
    Hex,
    Oct,
}

impl Default for Base {
    fn default() -> Self {
        Self::Dec
    }
}

impl<'a> TryFrom<&'a str> for Base {
    type Error = RuleParseError<&'a str>;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let base = match value {
            "dec" => Self::Dec,
            "hex" => Self::Hex,
            "oct" => Self::Oct,
            _ => {
                return Err(RuleParseError::Other(format!("invalid base: {}", value)));
            }
        };
        Ok(base)
    }
}

fn parse_op(input: &str) -> IResult<&str, ByteMathOperator, RuleParseError<&str>> {
    let (input, token) = parse_token(input)?;
    let op = ByteMathOperator::try_from(token).map_err(nom::Err::Error)?;
    Ok((input, op))
}

fn parse_rvalue(input: &str) -> IResult<&str, Rvalue, RuleParseError<&str>> {
    let (input, rvalue) = parse_token(input)?;
    if let Ok(value) = rvalue.parse::<i64>() {
        Ok((input, Rvalue::Value(value)))
    } else {
        Ok((input, Rvalue::Name(rvalue.to_string())))
    }
}

pub fn parse_byte_math(mut input: &str) -> IResult<&str, ByteMath, RuleParseError<&str>> {
    // Required values.
    let mut bytes = None;
    let mut offset = None;
    let mut oper = None;
    let mut rvalue = None;
    let mut result = None;

    // Optional values with defaults.
    let mut relative = false;
    let mut endian = Endian::default();
    let mut dce = false;
    let mut base = Base::default();
    let mut bitmask = 0;

    let mut keyword;
    loop {
        (input, keyword) = parse_token(input)?;
        match keyword {
            "bytes" => {
                let (i, v) = parse_number::<i64>(input)?;
                input = i;
                bytes = Some(v);
            }
            "offset" => {
                let (i, v) = parse_number::<i64>(input)?;
                input = i;
                offset = Some(v);
            }
            "oper" => {
                let (i, v) = parse_op(input)?;
                input = i;
                oper = Some(v);
            }
            "rvalue" => {
                let (i, v) = parse_rvalue(input)?;
                input = i;
                rvalue = Some(v);
            }
            "result" => {
                let (i, v) = parse_token(input)?;
                input = i;
                result = Some(v);
            }
            "relative" => relative = true,
            "dce" => dce = true,
            "endian" => {
                let (i, v) = parse_token(input)?;
                endian = Endian::try_from(v).map_err(nom::Err::Error)?;
                input = i;
            }
            "string" => {
                let (i, v) = parse_token(input)?;
                base = Base::try_from(v).map_err(nom::Err::Error)?;
                input = i;
            }
            "bitmask" => {
                let (i, _) = parse_tag("0x")(input)?;
                let (i, v) = parse_token(i)?;
                bitmask = u32::from_str_radix(v, 16)
                    .map_err(|_| nom::Err::Error(RuleParseError::BadByteMathBitMask))?;
                input = i;
            }
            _ => {
                return Err(nom::Err::Error(RuleParseError::BadByteMathKeyword(
                    keyword.to_string(),
                )));
            }
        }

        match parse_tag(",")(input) {
            Err(_) => break,
            Ok((i, _)) => input = i,
        }
    }

    let bytes = bytes.ok_or_else(|| Error(RuleParseError::MissingOption("bytes".to_string())))?;
    let offset =
        offset.ok_or_else(|| Error(RuleParseError::MissingOption("offset".to_string())))?;
    let oper = oper.ok_or_else(|| Error(RuleParseError::MissingOption("oper".to_string())))?;
    let rvalue =
        rvalue.ok_or_else(|| Error(RuleParseError::MissingOption("rvalue".to_string())))?;
    let result =
        result.ok_or_else(|| Error(RuleParseError::MissingOption("result".to_string())))?;

    // unimplemented!()

    Ok((
        input,
        ByteMath {
            bytes,
            offset,
            oper,
            rvalue,
            result: result.to_string(),
            relative,
            endian,
            base,
            dce,
            bitmask,
        },
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_token() {
        let r = parse_token("foo").unwrap();
        assert_eq!(r, ("", "foo"));

        let r = parse_token("foo;").unwrap();
        assert_eq!(r, (";", "foo"));

        let r = parse_token("foo\n").unwrap();
        assert_eq!(r, ("\n", "foo"));
    }

    #[test]
    fn test_parse_byte_math() {
        let (_, bytemath) = parse_byte_math(
            "bytes 4, offset 3933, oper +, rvalue 5, result output, bitmask 0xffff",
        )
        .unwrap();
        assert_eq!(bytemath.bitmask, 0xffff);
    }

    /// Test byte_math values from Snort source code.
    #[test]
    fn test_snort_examples() {
        let rule = r#"bytes 4,oper +,rvalue 123, offset 12,result var"#;
        let bm = parse_byte_math(rule).unwrap().1;
        assert_eq!(
            bm,
            ByteMath {
                base: Base::Dec,
                bitmask: 0,
                bytes: 4,
                offset: 12,
                endian: Endian::Big,
                dce: false,
                oper: ByteMathOperator::Add,
                relative: false,
                result: "var".to_string(),
                rvalue: Rvalue::Value(123),
            }
        );

        let rule = r#"bytes 1,oper <<,rvalue 123, offset 12,result var"#;
        let bm = parse_byte_math(rule).unwrap().1;
        assert_eq!(
            bm,
            ByteMath {
                base: Base::Dec,
                bitmask: 0,
                bytes: 1,
                offset: 12,
                endian: Endian::Big,
                dce: false,
                oper: ByteMathOperator::Lshift,
                relative: false,
                result: "var".to_string(),
                rvalue: Rvalue::Value(123),
            }
        );

        let rule =
            r#"oper /,rvalue 2, relative, result OFF1,offset 0, endian big,bytes 1,bitmask 0xA"#;
        let bm = parse_byte_math(rule).unwrap().1;
        assert_eq!(
            bm,
            ByteMath {
                base: Base::Dec,
                bitmask: 0xa,
                bytes: 1,
                offset: 0,
                endian: Endian::Big,
                dce: false,
                oper: ByteMathOperator::Div,
                relative: true,
                result: "OFF1".to_string(),
                rvalue: Rvalue::Value(2),
            }
        );
    }
}
