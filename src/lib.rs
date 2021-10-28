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

pub mod ffi;

use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::{alphanumeric1, multispace0};
use nom::combinator::{opt, rest};
use nom::error::ErrorKind;
use nom::error::ParseError;
use nom::sequence::{preceded, tuple};
use nom::Err::Error;
use nom::IResult;
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;

static WHITESPACE: &str = " \t\r\n";

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

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum Direction {
    #[cfg_attr(feature = "serde_support", serde(rename = "single"))]
    Single,
    #[cfg_attr(feature = "serde_support", serde(rename = "both"))]
    Both,
}

/// Parse all characters up until the next whitespace character.
fn take_until_whitespace(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    nom::bytes::complete::is_not(WHITESPACE)(input)
}

/// Parses a list of tokens in the rule address and port format.
///
/// For convenience, parsing a non-list formatted token is supported, returning a vector
/// of just that single item.
fn parse_token_list(input: &str) -> IResult<&str, Vec<String>, RuleParseError<&str>> {
    let mut output = vec![];

    // If the input doesn't look like a list, parse it as a whitespace delimited token returning a
    // single entry list.
    if !input.starts_with('[') {
        let (rem, token) = take_until_whitespace(input)?;
        output.push(token.to_string());
        return Ok((rem, output));
    }

    let (mut input, _start_tag) = nom::bytes::complete::tag("[")(input)?;
    let mut in_list = 1;
    loop {
        if in_list == 0 || input.is_empty() {
            break;
        }
        match input.chars().next() {
            Some('[') => {
                in_list += 1;
                input = &input[1..];
                continue;
            }
            Some(']') => {
                // End of list, usually when we're closing nested lists.
                in_list -= 1;
                input = &input[1..];
                continue;
            }
            Some(',') => {
                // List delimiter, would be found here after list close.
                input = &input[1..];
                continue;
            }
            Some(' ') => {
                input = &input[1..];
                continue;
            }
            _ => {}
        }

        // Take until list delimiter or end of list.
        let (rem, entry) = nom::bytes::complete::is_not(",]")(input)?;
        output.push(entry.trim().to_string());
        match rem.chars().next() {
            Some(',') => {
                input = &rem[1..];
            }
            Some(']') => {
                in_list -= 1;
                input = &rem[1..];
            }
            _ => {
                input = rem;
            }
        }
    }

    if in_list > 0 {
        return Err(nom::Err::Error(RuleParseError::UnterminatedList));
    }

    Ok((input, output))
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct NewRule {
    // The header.
    action: String,
    proto: String,
    src_addr: Vec<String>,
    src_port: Vec<String>,
    direction: Direction,
    dst_addr: Vec<String>,
    dst_port: Vec<String>,

    // Common fields/options, which should occur once per rule.
    message: String,
    sid: u64,
    rev: u64,

    // And for the rest of the options where order matters.
    options: Vec<RuleOption>,
}

impl From<Rule> for NewRule {
    fn from(old: Rule) -> Self {
        let mut message = String::new();
        let mut options = vec![];
        let mut sid = 0;
        let mut rev = 0;
        for option in old.options {
            match option {
                RuleOption::Message(m) => {
                    message = m;
                }
                RuleOption::Sid(s) => {
                    sid = s;
                }
                RuleOption::Rev(r) => {
                    rev = r;
                }
                _ => {
                    options.push(option);
                }
            }
        }

        NewRule {
            action: old.header.action,
            proto: old.header.proto,
            src_addr: old.header.src_addr,
            src_port: old.header.src_port,
            direction: old.header.direction,
            dst_addr: old.header.dst_addr,
            dst_port: old.header.dst_port,
            message,
            sid,
            rev,
            options,
        }
    }
}
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct Header {
    action: String,
    proto: String,
    src_addr: Vec<String>,
    src_port: Vec<String>,
    direction: Direction,
    dst_addr: Vec<String>,
    dst_port: Vec<String>,
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum RuleOption {
    #[cfg_attr(feature = "serde_support", serde(rename = "msg"))]
    Message(String),
    #[cfg_attr(feature = "serde_support", serde(rename = "sid"))]
    Sid(u64),
    #[cfg_attr(feature = "serde_support", serde(rename = "rev"))]
    Rev(u64),
    #[cfg_attr(feature = "serde_support", serde(rename = "byte_jump"))]
    ByteJump(ByteJumpOption),
    #[cfg_attr(feature = "serde_support", serde(rename = "depth"))]
    Depth(u64),
    #[serde(rename = "distance")]
    Distance(Distance),
    #[serde(rename = "flow")]
    Flow(String),
    #[serde(rename = "flowbits")]
    Flowbits(Flowbits),
    #[serde(rename = "dsize")]
    Dsize(String),
    #[serde(rename = "content")]
    Content(String),
    #[serde(rename = "offset")]
    Offset(u64),
    #[serde(rename = "pcre")]
    Pcre(String),
    #[serde(rename = "isdataat")]
    IsDataAt(String),
    #[serde(rename = "reference")]
    Reference(String),
    #[serde(rename = "classtype")]
    Classtype(String),
    #[serde(rename = "metadata")]
    Metadata(String),

    // Option type for an unknown option with a value.
    #[serde(rename = "unknown")]
    ValueOption(ValueOption),

    // Option type for an unknown modifier or option without a value.
    #[cfg_attr(feature = "serde_support", serde(rename = "modifier"))]
    Modifier(ModifierOption),
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct ValueOption {
    pub name: String,
    pub val: String,
}

/// Modifier option type.
///
/// This is any option without a value, usually a modifier.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct ModifierOption {
    pub name: String,
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct Rule {
    header: Header,
    options: Vec<RuleOption>,
}

fn parse_direction(input: &str) -> IResult<&str, Direction, RuleParseError<&str>> {
    let (input, direction) = alt((tag("->"), tag("<>")))(input)?;
    match direction {
        "->" => Ok((input, Direction::Single)),
        "<>" => Ok((input, Direction::Both)),
        _ => Err(nom::Err::Error(RuleParseError::InvalidDirection(
            direction.to_string(),
        ))),
    }
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum Distance {
    #[cfg_attr(feature = "serde_support", serde(rename = "value"))]
    Value(i64),
    #[cfg_attr(feature = "serde_support", serde(rename = "varname"))]
    Var(String),
}

impl Distance {
    fn parse(input: &str) -> IResult<&str, Self, RuleParseError<&str>> {
        let (_, input) = preceded(multispace0, take_until_whitespace)(input)?;
        if let Ok(distance) = input.parse() {
            Ok((input, Self::Value(distance)))
        } else {
            Ok((input, Self::Var(input.to_string())))
        }
    }
}

fn parse_header(input: &str) -> IResult<&str, Header, RuleParseError<&str>> {
    let (rem, (action, proto, src_addr, src_port, direction, dst_addr, dst_port)) =
        nom::sequence::tuple((
            preceded(multispace0, take_until_whitespace),
            preceded(multispace0, take_until_whitespace),
            preceded(multispace0, parse_token_list),
            preceded(multispace0, parse_token_list),
            preceded(multispace0, parse_direction),
            preceded(multispace0, parse_token_list),
            preceded(multispace0, parse_token_list),
        ))(input)?;
    Ok((
        rem,
        Header {
            action: action.to_string(),
            proto: proto.to_string(),
            src_addr,
            src_port,
            direction,
            dst_addr,
            dst_port,
        },
    ))
}

/// Look for the end options terminated.
///
/// Simply a ')' with any amount of leading whitespace.
fn option_end_parser(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
    preceded(multispace0, tag(")"))(input)
}

pub fn parse_rule(input: &str) -> IResult<&str, Rule, RuleParseError<&str>> {
    let (input, header) = parse_header(input)?;
    // TODO: Map error no some no start of options error.
    let (input, _start_of_options) = preceded(multispace0, tag("("))(input)?;

    // Parse the options in a loop. Using a combinator like many1 will eat the error if an option
    // parser fails.
    let mut options = vec![];
    let mut input = input;
    loop {
        if let Ok((rem, _)) = option_end_parser(input) {
            input = rem;
            break;
        }
        let (trailer, option) = parse_option(input)?;
        options.push(option);
        input = trailer;
    }

    Ok((input, Rule { header, options }))
}

fn get_option_value(input: &str) -> IResult<&str, &str, RuleParseError<&str>> {
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

fn parse_u64<'a>(input: &'a str, context: &str) -> IResult<&'a str, u64, RuleParseError<&'a str>> {
    let (_, input) = preceded(multispace0, take_until_whitespace)(input)?;
    let val = input.parse().map_err(|_| {
        nom::Err::Error(RuleParseError::IntegerParseError(format!(
            "{}: {}",
            context, input
        )))
    })?;
    Ok((input, val))
}

fn parse_option(input: &str) -> IResult<&str, RuleOption, RuleParseError<&str>> {
    // First get the option name.
    let (input, name) = preceded(multispace0, nom::bytes::complete::is_not(";:"))(input)?;
    let (input, sep) = preceded(multispace0, nom::character::complete::one_of(";:"))(input)?;
    if sep == ';' {
        Ok((
            input,
            RuleOption::Modifier(ModifierOption {
                name: name.to_string(),
            }),
        ))
    } else {
        let (input, value) = get_option_value(input)?;
        let option = match name {
            "byte_jump" => RuleOption::ByteJump(ByteJumpOption::parse(value)?.1),
            "classtype" => RuleOption::Classtype(value.to_owned()),
            "content" => RuleOption::Content(value.to_owned()),
            "depth" => RuleOption::Depth(parse_u64(value, "depth")?.1),
            "distance" => RuleOption::Distance(Distance::parse(value)?.1),
            "dsize" => RuleOption::Dsize(value.to_owned()),
            "flow" => RuleOption::Flow(value.to_owned()),
            "flowbits" => RuleOption::Flowbits(parse_flowbits(value)?.1),
            "isdataat" => RuleOption::IsDataAt(value.to_owned()),
            "metadata" => RuleOption::Metadata(value.to_owned()),
            "msg" => RuleOption::Message(strip_quotes(value)),
            "offset" => RuleOption::Offset(parse_u64(value, "offset")?.1),
            "pcre" => RuleOption::Pcre(value.to_owned()),
            "reference" => RuleOption::Reference(value.to_owned()),
            "rev" => RuleOption::Rev(parse_u64(value, "rev")?.1),
            "sid" => RuleOption::Sid(parse_u64(value, "sid")?.1),
            _ => RuleOption::ValueOption(ValueOption {
                name: name.to_string(),
                val: value.to_string(),
            }),
        };
        Ok((input, option))
    }
}

/// Remove quotes from a string, but preserve any escaped quotes.
fn strip_quotes(input: &str) -> String {
    let mut escaped = false;
    let mut out: Vec<char> = Vec::new();

    for c in input.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else {
            match c {
                '"' => {}
                '\\' => {
                    escaped = true;
                }
                _ => {
                    out.push(c);
                }
            }
        }
    }

    out.iter().collect()
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub enum Endian {
    #[cfg_attr(feature = "serde_support", serde(rename = "big"))]
    Big,
    #[cfg_attr(feature = "serde_support", serde(rename = "little"))]
    Little,
}

impl Default for Endian {
    fn default() -> Self {
        Self::Big
    }
}

/// Check if a value is the same as its default.
///
/// Useful for Serde's skip_serializing_if to suppress defaults being output.
fn is_default<T>(val: &T) -> bool
where
    T: Default + PartialEq,
{
    (*val) == Default::default()
}

/// Structured byte_jump rule option.
///
/// Serde stuff add for easy serialization even though it clutters up the struct a bit.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct ByteJumpOption {
    pub count: usize,
    pub offset: i64,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub relative: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub multiplier: usize,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub endian: Endian,

    // These can be bundled into an enum.
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub string: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub hex: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub dec: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub oct: bool,

    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub align: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub from_beginning: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub from_end: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub post_offset: i64,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub dce: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub bitmask: u64,
}

impl ByteJumpOption {
    fn parse(input: &str) -> IResult<&str, ByteJumpOption, RuleParseError<&str>> {
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

        let mut byte_jump = ByteJumpOption::default();

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
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum FlowbitsEnum {
    #[cfg_attr(feature = "serde_support", serde(rename = "noalert"))]
    NoAlert,
    #[cfg_attr(feature = "serde_support", serde(rename = "set"))]
    Set(String),
    #[cfg_attr(feature = "serde_support", serde(rename = "isset"))]
    IsSet(String),
    #[cfg_attr(feature = "serde_support", serde(rename = "toggle"))]
    Toggle(String),
    #[cfg_attr(feature = "serde_support", serde(rename = "unset"))]
    Unset(String),
    #[cfg_attr(feature = "serde_support", serde(rename = "isnotset"))]
    IsNotSet(String),
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub enum FlowbitCommand {
    #[cfg_attr(feature = "serde_support", serde(rename = "noalert"))]
    NoAlert,
    #[cfg_attr(feature = "serde_support", serde(rename = "set"))]
    Set,
    #[cfg_attr(feature = "serde_support", serde(rename = "isset"))]
    IsSet,
    #[cfg_attr(feature = "serde_support", serde(rename = "toggle"))]
    Toggle,
    #[cfg_attr(feature = "serde_support", serde(rename = "unset"))]
    Unset,
    #[cfg_attr(feature = "serde_support", serde(rename = "isnotset"))]
    IsNotSet,
}

use std::fmt::{Display, Formatter};

impl Display for FlowbitCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::IsNotSet => "isnotset",
            Self::IsSet => "isset",
            Self::Toggle => "toggle",
            Self::Unset => "unset",
            Self::NoAlert => "noalert",
            Self::Set => "set",
        };
        write!(f, "{}", label)
    }
}

impl FromStr for FlowbitCommand {
    // Use nom::Err to satisfy ? in parser.
    type Err = nom::Err<RuleParseError<&'static str>>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "noalert" => Ok(Self::NoAlert),
            "set" => Ok(Self::Set),
            "isset" => Ok(Self::IsSet),
            "toggle" => Ok(Self::Toggle),
            "unset" => Ok(Self::Unset),
            "isnotset" => Ok(Self::IsNotSet),
            _ => Err(nom::Err::Error(RuleParseError::Flowbit(format!(
                "unknown command: {}",
                s
            )))),
        }
    }
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct Flowbits {
    pub command: FlowbitCommand,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Vec::is_empty")
    )]
    pub names: Vec<String>,
}

pub fn parse_flowbits(input: &str) -> IResult<&str, Flowbits, RuleParseError<&str>> {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_parse_flowbits() {
        let (_, _flowbits) = parse_flowbits("set,foo.bar").unwrap();
        let (_, _flowbits) = parse_flowbits("set,foo | bar").unwrap();
        let (_, _flowbits) = parse_flowbits("noalert").unwrap();
    }

    #[test]
    fn test_parse_header() {
        let (rem, input) = parse_header("alert tcp 1.1.1.1 any -> 2.2.2.2 any").unwrap();
        assert_eq!(rem, "");
        assert_eq!(&input.action, "alert");
        assert_eq!(&input.proto, "tcp");
    }

    #[test]
    fn test_parse_multiline_header() {
        let (rem, _header) = parse_header(
            r#"alert any 
                        any any 
                        -> 
                        any any
                        
              alert any any any -> any any
        "#,
        )
        .unwrap();
        assert_eq!(rem.trim(), "alert any any any -> any any");
    }

    #[test]
    fn test_parse_direction() {
        let (_rem, direction) = parse_direction("->").unwrap();
        assert_eq!(direction, Direction::Single);

        let (_rem, direction) = parse_direction("<>").unwrap();
        assert_eq!(direction, Direction::Both);
    }

    #[test]
    fn test_parse_addr() {
        let (_rem, addrs) = parse_token_list("[1.1.1.1]").unwrap();
        assert_eq!(&addrs, &["1.1.1.1"]);

        let (_rem, addrs) = parse_token_list("[1.1.1.1,2.2.2.2]").unwrap();
        assert_eq!(&addrs, &["1.1.1.1", "2.2.2.2"]);

        let (rem, addrs) =
            parse_token_list("[1.1.1.1, [2.2.2.2, 3.3.3.3], $HOME_NET] any").unwrap();
        assert_eq!(&addrs, &["1.1.1.1", "2.2.2.2", "3.3.3.3", "$HOME_NET"]);
        assert_eq!(rem, " any");

        let result = parse_token_list("[1.1.1.1,2.2.2.2");
        assert_eq!(
            result,
            Err(nom::Err::Error(RuleParseError::UnterminatedList))
        );

        let (_rem, addrs) = parse_token_list("1.1.1.1").unwrap();
        assert_eq!(&addrs, &["1.1.1.1"]);
    }

    #[test]
    fn test_parse_quoted_string() {
        assert_eq!(
            strip_quotes(r#""some quoted \" string""#),
            r#"some quoted " string"#
        );

        assert_eq!(
            strip_quotes(r#""some quoted \\ string""#),
            r#"some quoted \ string"#
        );
    }

    #[test]
    fn test_parse_rule() {
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
        let (rem, rule) = parse_rule(input).unwrap();
        assert_eq!(rem, "");
        assert_eq!(&rule.header.action, "alert");
        assert_eq!(&rule.header.dst_addr, &["$HOME_NET"]);
        assert_eq!(&rule.header.dst_port, &["445"]);
    }

    #[test]
    fn test_parse_byte_jump() {
        assert!(ByteJumpOption::parse("4").is_err());
        assert!(ByteJumpOption::parse("4,12").is_ok());

        let input = "4,12,relative,little,multiplier 2";
        let (_, byte_jump) = ByteJumpOption::parse(input).unwrap();
        assert_eq!(byte_jump.count, 4);
        assert_eq!(byte_jump.offset, 12);
        assert_eq!(byte_jump.relative, true);
        assert_eq!(byte_jump.endian, Endian::Little);
        assert_eq!(byte_jump.multiplier, 2);

        // Same as above but with a bitmask.
        let input = "4,12,relative,little,multiplier 2,bitmask 0x3c";
        let (_, byte_jump) = ByteJumpOption::parse(input).unwrap();
        assert_eq!(byte_jump.bitmask, 0x3c);

        let input = "4,-18,relative,little,from_beginning, post_offset 1";
        let (_, _byte_jump) = ByteJumpOption::parse(input).unwrap();
    }

    #[test]
    fn test_parse_option_value() {
        let (rem, value) = get_option_value("value;").unwrap();
        assert_eq!(rem, "");
        assert_eq!(value, "value");

        let (rem, value) = get_option_value("   value;").unwrap();
        assert_eq!(rem, "");
        assert_eq!(value, "value");

        let (rem, value) = get_option_value("   value ;").unwrap();
        assert_eq!(rem, "");
        assert_eq!(value, "value ");

        let (rem, value) = get_option_value("   value ;next option").unwrap();
        assert_eq!(rem, "next option");
        assert_eq!(value, "value ");
    }

    #[test]
    fn test_parse_pcre_option() {
        let input = r#"pcre:"/^\x22[^\x22]*\x7b[^\x22]*\x7d[^\x22]*\x22[^\x22]*\x22{2}/Rm";"#;
        let (_rem, option) = parse_option(input).unwrap();
        if let RuleOption::ValueOption(option) = option {
            let stripped = strip_quotes(&option.val);
            dbg!(stripped);
        }
    }
}
