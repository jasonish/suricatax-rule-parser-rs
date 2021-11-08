// Copyright 2021 Open Information Security Foundation
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

pub mod ffi;
pub mod parsers;
pub mod types;
pub mod util;

use nom::bytes::complete::tag;
use nom::character::complete::multispace0;
use nom::error::ErrorKind;
use nom::error::ParseError;
use nom::sequence::{preceded, tuple};
use nom::IResult;
use serde::Deserialize;
use serde::Serialize;
use types::*;

/// Custom rule parse errors.
///
/// Implemented based on the Nom example for implementing custom errors.
#[derive(Debug, PartialEq)]
pub enum RuleParseError<I> {
    UnterminatedList,
    UnterminatedRuleOptionValue,
    InvalidSid(String),
    InvalidDirection(String),
    InvalidByteJump(String),
    IntegerParseError(String),
    Flowbit(String),

    // Other...
    Other(String),

    // Error thrown when an attempt convert an internal rule element to a public
    // rule option. Examples of such elements that are not exposed as public
    // options are content modifiers as they are hoisted into the content option
    // itself, as well as other singleton values such as the message, sid, and
    // rev.
    PrivateElement(String),

    NotList,
    Nom(I, ErrorKind),
}

impl<I> ParseError<I> for RuleParseError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        RuleParseError::Nom(input, kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

#[cfg_attr(
    feature = "serde_support",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum Element {
    // Header elements.
    Action(String),
    Protocol(String),
    SrcAddr(String),
    SrcPort(String),
    Direction(Direction),
    DstAddr(String),
    DstPort(String),

    // Body (option) elements.
    ByteJump(types::ByteJump),
    Classtype(String),
    Content(Content),
    Depth(u64),
    Dsize(String),
    Distance(Distance),
    EndsWith(bool),
    FastPattern(bool),
    FileData(FileData),
    Flow(String),
    Flowbits(Flowbits),
    FtpBounce(bool),
    IsDataAt(String),
    Message(String),
    Metadata(String),
    NoAlert(bool),
    NoCase(bool),
    Offset(u64),
    Pcre(String),
    RawBytes(bool),
    Reference(String),
    Rev(u64),
    Sid(u64),
    StartsWith(bool),
    Within(Within),

    // A generic option, used for unknown rule options.
    GenericOption(GenericOption),
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct GenericOption {
    pub name: String,
    pub val: Option<String>,
}

/// Parse the value for an option.
///
/// This parser expects the input to be the first character after the ':'
/// following an option name. It will return all the characters up to but not
/// including the option terminator ';', handling all escaped occurrences of the
/// option terminator.
///
/// The remaining input returned does not contain the option terminator.
pub(crate) fn parse_option_value(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    let mut escaped = false;
    let mut end = 0;
    let mut terminated = false;

    // First jump over any leading whitespace.
    let (input, _) = multispace0(input)?;

    for (i, c) in input.chars().enumerate() {
        end = i;
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
        Err(nom::Err::Error(RuleParseError::UnterminatedRuleOptionValue))
    } else {
        Ok((&input[end + 1..], &input[0..end]))
    }
}

pub(crate) fn parse_option_element(input: &str) -> IResult<&str, Element, RuleParseError<&str>> {
    // First get the option name.
    let (input, name) = preceded(multispace0, nom::bytes::complete::is_not(";:"))(input)?;
    let (input, sep) = preceded(multispace0, nom::character::complete::one_of(";:"))(input)?;
    if sep == ';' {
        let option = match name {
            "endswith" => Element::EndsWith(true),
            "fast_pattern" => Element::FastPattern(true),
            "file_data" => Element::FileData(FileData),
            "ftpbounce" => Element::FtpBounce(true),
            "noalert" => Element::NoAlert(true),
            "nocase" => Element::NoCase(true),
            "rawbytes" => Element::RawBytes(true),
            "startswith" => Element::StartsWith(true),
            _ => Element::GenericOption(GenericOption {
                name: name.to_string(),
                val: None,
            }),
        };
        Ok((input, option))
    } else {
        let (input, value) = parse_option_value(input)?;
        let option = match name {
            "byte_jump" => Element::ByteJump(parsers::parse_byte_jump(value)?.1),
            "classtype" => Element::Classtype(value.to_owned()),
            "content" => Element::Content(types::Content::new(value.to_owned())),
            "depth" => Element::Depth(parsers::parse_u64(value, "depth")?.1),
            "distance" => {
                Element::Distance(types::Distance(parsers::parse_count_or_name(value)?.1))
            }
            "within" => Element::Within(types::Within(parsers::parse_count_or_name(value)?.1)),
            "dsize" => Element::Dsize(value.to_owned()),
            "flow" => Element::Flow(value.to_owned()),
            "flowbits" => Element::Flowbits(parsers::parse_flowbits(value)?.1),
            "isdataat" => Element::IsDataAt(value.to_owned()),
            "metadata" => Element::Metadata(value.to_owned()),
            "msg" => Element::Message(util::strip_quotes(value)),
            "offset" => Element::Offset(parsers::parse_u64(value, "offset")?.1),
            "pcre" => Element::Pcre(value.to_owned()),
            "reference" => Element::Reference(value.to_owned()),
            "rev" => Element::Rev(parsers::parse_u64(value, "rev")?.1),
            "sid" => Element::Sid(parsers::parse_u64(value, "sid")?.1),
            _ => Element::GenericOption(GenericOption {
                name: name.to_string(),
                val: Some(value.to_string()),
            }),
        };
        Ok((input, option))
    }
}

/// Parse a rule into individual element.
///
/// For the header, each item like action, source address, etc is considered
/// elemenent. For rule options, the parsed option is an element.
///
/// The result is a vector of parsed elements in the same order as found in the
/// original rule.
pub fn parse_elements(input: &str) -> IResult<&str, Vec<Element>, RuleParseError<&str>> {
    let mut elements = Vec::new();

    // Header elements.
    let (input, (action, proto, src_addr, src_port, direction, dst_addr, dst_port)) = tuple((
        preceded(multispace0, parsers::take_until_whitespace),
        preceded(multispace0, parsers::take_until_whitespace),
        preceded(multispace0, parsers::parse_list),
        preceded(multispace0, parsers::parse_list),
        preceded(multispace0, parsers::parse_direction),
        preceded(multispace0, parsers::parse_list),
        preceded(multispace0, parsers::parse_list),
    ))(input)?;
    elements.push(Element::Action(action.into()));
    elements.push(Element::Protocol(proto.into()));
    elements.push(Element::SrcAddr(src_addr.into()));
    elements.push(Element::SrcPort(src_port.into()));
    elements.push(Element::Direction(direction));
    elements.push(Element::DstAddr(dst_addr.into()));
    elements.push(Element::DstPort(dst_port.into()));

    // Now find the start of options indicator '('.
    let (input, _start_of_options) = preceded(multispace0, tag("("))(input)?;

    fn parse_option_end(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
        preceded(multispace0, tag(")"))(input)
    }

    // Nom some options.
    let mut input = input;
    loop {
        if let Ok((rem, _)) = parse_option_end(input) {
            input = rem;
            break;
        }
        let (rem, option) = parse_option_element(input)?;
        elements.push(option);
        input = rem;
    }

    Ok((input, elements))
}

/// Reduce elements.
///
/// The element reducers combines some elements together such as adding
/// modifiers to a content element then removing the content element from the
/// element list.
///
/// This includes some validation like not allowing distance or depth unless
/// there is a preceding content element to add them to.
pub fn reduce_elements(
    elements: Vec<Element>,
) -> IResult<&'static str, Vec<Element>, RuleParseError<&'static str>> {
    let mut reduced = Vec::with_capacity(elements.len());

    fn make_error(
        error: RuleParseError<&'static str>,
    ) -> Result<(), nom::Err<RuleParseError<&'static str>>> {
        Err(nom::Err::Error(error))
    }

    for element in elements {
        let mut prev_content = None;
        for element in reduced.iter_mut().rev() {
            match element {
                Element::Content(_) => {
                    prev_content = Some(element);
                    break;
                }
                // Leave set to None on sticky buffer.
                Element::GenericOption(option) => match option.name.as_ref() {
                    "tls.sni" | "http.uri" => {
                        break;
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        match element {
            // Modifiers.
            Element::Depth(depth) => {
                if let Some(Element::Content(content)) = prev_content {
                    content.depth = depth;
                } else {
                    make_error(RuleParseError::Other(
                        "depth not preceded by content".into(),
                    ))?;
                }
            }
            Element::Distance(distance) => {
                if let Some(Element::Content(content)) = prev_content {
                    content.distance = distance;
                } else {
                    make_error(RuleParseError::Other(
                        "distance not preceded by content".into(),
                    ))?;
                }
            }
            Element::EndsWith(endswith) => {
                if let Some(Element::Content(content)) = prev_content {
                    content.endswith = endswith;
                } else {
                    make_error(RuleParseError::Other(
                        "endswith not preceded by content".into(),
                    ))?;
                }
            }
            Element::FastPattern(fast_pattern) => {
                if let Some(Element::Content(content)) = prev_content {
                    content.fast_pattern = fast_pattern;
                } else {
                    make_error(RuleParseError::Other(
                        "fast_pattern not preceded by content".into(),
                    ))?;
                }
            }
            Element::NoCase(nocase) => {
                if let Some(Element::Content(content)) = prev_content {
                    content.nocase = nocase;
                } else {
                    make_error(RuleParseError::Other(
                        "nocase not preceded by content".into(),
                    ))?;
                }
            }
            Element::Offset(offset) => {
                if let Some(Element::Content(content)) = prev_content {
                    content.offset = offset;
                } else {
                    make_error(RuleParseError::Other(
                        "offset not preceded by content".into(),
                    ))?;
                }
            }
            Element::StartsWith(startswith) => {
                if let Some(Element::Content(content)) = prev_content {
                    content.startswith = startswith;
                } else {
                    make_error(RuleParseError::Other(
                        "startswith not preceded by content".into(),
                    ))?;
                }
            }
            Element::Within(within) => {
                if let Some(Element::Content(content)) = prev_content {
                    content.within = within;
                } else {
                    make_error(RuleParseError::Other(
                        "within not preceded by content".into(),
                    ))?;
                }
            }
            _ => {
                reduced.push(element);
            }
        }
    }

    Ok(("", reduced))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_parse_flowbits() {
        let (_, _flowbits) = parsers::parse_flowbits("set,foo.bar").unwrap();
        let (_, _flowbits) = parsers::parse_flowbits("set,foo | bar").unwrap();
        let (_, _flowbits) = parsers::parse_flowbits("noalert").unwrap();
    }

    #[test]
    fn test_parse_direction() {
        let (_rem, direction) = parsers::parse_direction("->").unwrap();
        assert_eq!(direction, types::Direction::Single);

        let (_rem, direction) = parsers::parse_direction("<>").unwrap();
        assert_eq!(direction, types::Direction::Both);
    }

    #[test]
    fn test_parse_quoted_string() {
        assert_eq!(
            util::strip_quotes(r#""some quoted \" string""#),
            r#"some quoted " string"#
        );

        assert_eq!(
            util::strip_quotes(r#""some quoted \\ string""#),
            r#"some quoted \ string"#
        );
    }

    #[test]
    fn test_parse_elements() {
        let input = r#"alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
            msg:"ET DOS NetrWkstaUserEnum Request with large Preferred Max Len";
            flow:established,to_server; content:"|ff|SMB"; content:"|10 00 00 00|";
            distance:0; content:"|02 00|";
            distance:14;
            within:2;
            byte_jump:4,12,relative,little,multiplier 2;
            content:"|00 00 00 00 00 00 00 00|";
            distance:12;
            within:8;
            byte_test:4,>,2,0,relative;
            reference:cve,2006-6723;
            reference:url,doc.emergingthreats.net/bin/view/Main/2003236;
            classtype:attempted-dos;
            sid:2003236;
            rev:4;
            metadata:created_at 2010_07_30, updated_at 2010_07_30;)"#;
        let (rem, _elements) = parse_elements(input).unwrap();
        assert_eq!(rem, "");
    }
    #[test]
    fn test_parse_byte_jump() {
        assert!(parsers::parse_byte_jump("4").is_err());
        assert!(parsers::parse_byte_jump("4,12").is_ok());

        let input = "4,12,relative,little,multiplier 2";
        let (_, byte_jump) = parsers::parse_byte_jump(input).unwrap();
        assert_eq!(byte_jump.count, 4);
        assert_eq!(byte_jump.offset, 12);
        assert_eq!(byte_jump.relative, true);
        assert_eq!(byte_jump.endian, types::Endian::Little);
        assert_eq!(byte_jump.multiplier, 2);

        // Same as above but with a bitmask.
        let input = "4,12,relative,little,multiplier 2,bitmask 0x3c";
        let (_, byte_jump) = parsers::parse_byte_jump(input).unwrap();
        assert_eq!(byte_jump.bitmask, 0x3c);

        let input = "4,-18,relative,little,from_beginning, post_offset 1";
        let (_, _byte_jump) = parsers::parse_byte_jump(input).unwrap();
    }

    #[test]
    fn test_parse_option_value() {
        let (rem, value) = parse_option_value("value;").unwrap();
        assert_eq!(rem, "");
        assert_eq!(value, "value");

        let (rem, value) = parse_option_value("   value;").unwrap();
        assert_eq!(rem, "");
        assert_eq!(value, "value");

        let (rem, value) = parse_option_value("   value ;").unwrap();
        assert_eq!(rem, "");
        assert_eq!(value, "value ");

        let (rem, value) = parse_option_value("   value ;next option").unwrap();
        assert_eq!(rem, "next option");
        assert_eq!(value, "value ");
    }

    #[test]
    fn test_parse_list() {
        let (_rem, list) = parsers::parse_list("[").unwrap();
        assert_eq!(_rem, "");
        assert_eq!(list, "[");

        let (_rem, list) = parsers::parse_list("[]a").unwrap();
        assert_eq!(_rem, "a");
        assert_eq!(list, "[]");

        let (_rem, list) = parsers::parse_list("[1,[1,2],[1,2,3]]a").unwrap();
        assert_eq!(_rem, "a");
        assert_eq!(list, "[1,[1,2],[1,2,3]]");

        let (_rem, list) = parsers::parse_list("[1,[1,2],[1, 2, 3  ]]a").unwrap();
        assert_eq!(_rem, "a");
        assert_eq!(list, "[1,[1,2],[1, 2, 3  ]]");
    }
}
