// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

use nom::Offset;
use parser::{RuleParser, RuleParserEvent};
use serde::{Deserialize, Serialize};

use options::{ByteJump, ByteTest, Content, Flow, Flowbits, IsDataAt, Pcre, Reference};
use parsers::ParseError;
use types::{ArrayElement, Direction, NumberOrReference};

mod ffi;
pub mod loader;
mod options;
pub mod parser;
mod parsers;
mod types;
mod util;

/// Rule parse errors.
///
/// This error type helps hide the details of the Nom based errors
/// used internally.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Error {
    pub offset: usize,
    pub msg: String,
    pub reason: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "error at offset {}: {} ({})",
            self.offset, self.msg, self.reason
        )
    }
}

impl std::error::Error for Error {}

impl Error {
    fn from_parse_error(err: ParseError<&str>, start: &str, context: &str) -> Self {
        let offset = start.offset(err.input);
        Error {
            offset,
            msg: context.to_string(),
            reason: err.kind.to_string(),
        }
    }

    /// Create an external error from a nom error.
    fn from_nom_error(err: nom::Err<ParseError<&str>>, start: &str, context: &str) -> Self {
        match err {
            nom::Err::Incomplete(_) => Error {
                offset: start.len(),
                msg: context.to_string(),
                reason: "incomplete".to_string(),
            },
            nom::Err::Failure(err) | nom::Err::Error(err) => {
                let offset = start.offset(err.input);
                Error {
                    offset,
                    msg: context.to_string(),
                    reason: err.kind.to_string(),
                }
            }
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub action: String,
    pub proto: String,
    pub src_ip: Vec<ArrayElement>,
    pub src_port: Vec<ArrayElement>,
    pub direction: Direction,
    pub dest_ip: Vec<ArrayElement>,
    pub dest_port: Vec<ArrayElement>,
    pub options: Vec<RuleOption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RuleOption {
    /// The name of the rule option.
    #[serde(skip)]
    pub name: String,
    /// The raw value of the rule option.
    #[serde(skip)]
    pub value: Option<String>,
    /// The parsed rule option, for options the parser understands.
    pub parsed: Parsed,
}

/// Custom serializer for RuleOption
///
/// Skips the raw name and value, and flattens the parsed struct up a
/// level.
///
/// Still not sure about this yet.
impl Serialize for RuleOption {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        // Just serialize parsed.
        self.parsed.serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Parsed {
    /// Use if there is no parser for the option.
    Unknown,

    /// A (sticky) buffer.
    Buffer(String),

    /// A modifier.
    Modifier(String),

    /// Transforms
    Transform(String),

    Ack(u64),
    AppLayerEvent(String),
    AppLayerProtocol(String),
    Asn1(String),
    Base64Decode(String),
    Bsize(String),
    ByteExtract(String),
    ByteJump(ByteJump),
    ByteTest(ByteTest),
    Classtype(String),
    Content(Content),
    Dataset(String),
    DceIface(String),
    DceOpnum(u64),
    DceRpcIface(String),
    DceRpcOpnum(u64),
    DecodeEvent(String),
    Depth(NumberOrReference<u64>),
    DetectionFilter(String),
    Distance(NumberOrReference<u64>),
    Dnp3Func(String),
    Dnp3Ind(String),
    DnsOpcode(u16),
    Dsize(String),
    FastPattern(Option<String>),
    Fileext(String),
    Flow(Flow),
    Flowbits(Flowbits),
    #[serde(rename = "flow.bytes_toserver")]
    FlowBytesToServer(String),
    Flowint(String),
    Fragbits(String),
    FragOffset(String),
    Ftpbounce,
    IcmpId(u16),
    IcmpSeq(u16),
    Icode(String),
    Id(u16),
    IpOpts(String),
    IpProto(String),
    IsDataAt(IsDataAt),
    Itype(String),
    Krb5ErrCode(String),
    Message(String),
    Metadata(Vec<String>),
    Noalert,
    Offset(NumberOrReference<u64>),
    Pcre(Pcre),
    Priority(u8),
    Rawbytes,
    Reference(Reference),
    Rev(u64),
    Sameip,
    Seq(u64),
    Sid(u64),
    SnmpVersion(String),
    SslState(String),
    SslVersion(String),
    StreamSize(String),
    Tag(String),
    Target(String),
    TcpFlags(String),
    Threshold(String),
    TlsFingerprint(String),
    TlsVersion(String),
    Tos(String),
    Ttl(String),
    UriContent(String),
    Urilen(String),
    Window(String),
    Within(NumberOrReference<u64>),
    Xbits(String),
}

pub fn parse_rule(buf: &str) -> Result<Rule, Error> {
    let parser = RuleParser::new(buf);

    let mut rule = Rule::default();

    for element in parser {
        match element? {
            RuleParserEvent::Action(action) => rule.action = action,
            RuleParserEvent::Protocol(protocol) => rule.proto = protocol,
            RuleParserEvent::SourceIp(src_ip) => rule.src_ip = src_ip,
            RuleParserEvent::SourcePort(src_port) => rule.src_port = src_port,
            RuleParserEvent::Direction(direction) => rule.direction = direction,
            RuleParserEvent::DestIp(dest_ip) => rule.dest_ip = dest_ip,
            RuleParserEvent::DestPort(dest_port) => rule.dest_port = dest_port,
            RuleParserEvent::StartOfOptions => (),
            RuleParserEvent::Option(option) => rule.options.push(option),
        }
    }

    Ok(rule)
}

#[cfg(test)]
mod test {
    use self::parser::RuleParserState;

    use super::*;

    #[test]
    fn test_parse_rule() {
        let input = "alert tcp any any = any any";
        let result = parse_rule(input);
        assert_eq!(
            result,
            Err(Error {
                offset: 18,
                msg: "direction".to_string(),
                reason: "invalid".to_string(),
            })
        );
        let err = result.unwrap_err();
        assert_eq!(&input[err.offset..], "= any any");

        let rule = r#"alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2019_07_26;)"#;
        let rule = parse_rule(rule).unwrap();
        assert_eq!(rule.action, "alert");
        assert_eq!(rule.proto, "ip");
        assert_eq!(rule.src_ip, vec![ArrayElement::String("any".to_string())]);
        assert_eq!(rule.src_port, vec![ArrayElement::String("any".to_string())]);
        assert_eq!(rule.direction, Direction::Single);
        assert_eq!(rule.dest_ip, vec![ArrayElement::String("any".to_string())]);
        assert_eq!(
            rule.dest_port,
            vec![ArrayElement::String("any".to_string())]
        );
        assert_eq!(rule.options.len(), 6);
        assert_eq!(rule.options[0].name, "msg");
        assert_eq!(
            rule.options[0].value,
            Some("\"GPL ATTACK_RESPONSE id check returned root\"".to_string())
        );
        assert_eq!(
            rule.options[1].value,
            Some("\"uid=0|28|root|29|\"".to_string())
        );
        assert_eq!(rule.options[1].name, "content");
        assert_eq!(rule.options[2].name, "classtype");
        assert_eq!(rule.options[2].value, Some("bad-unknown".to_string()));
        assert_eq!(rule.options[3].name, "sid");
        assert_eq!(rule.options[3].value, Some("2100498".to_string()));
        assert_eq!(rule.options[4].name, "rev");
        assert_eq!(rule.options[4].value, Some("7".to_string()));
        assert_eq!(rule.options[5].name, "metadata");
        assert_eq!(
            rule.options[5].value,
            Some("created_at 2010_09_23, updated_at 2019_07_26".to_string())
        );
    }

    #[test]
    fn test_rule_parser_iterator() {
        let rule = r#"alert tcp any any -> any any (msg:"test"; metadata:1,2,3;)"#;
        let iter = RuleParser::new(rule);
        let mut state = RuleParserState::Action;
        for element in iter {
            let element = element.unwrap();
            match element {
                RuleParserEvent::Action(action) => {
                    assert_eq!(state, RuleParserState::Action);
                    assert_eq!(action, "alert");
                    state = RuleParserState::Protocol;
                }
                RuleParserEvent::Protocol(proto) => {
                    assert_eq!(state, RuleParserState::Protocol);
                    assert_eq!(proto, "tcp");
                    state = RuleParserState::SourceIp;
                }
                RuleParserEvent::SourceIp(src_ip) => {
                    assert_eq!(state, RuleParserState::SourceIp);
                    assert_eq!(src_ip, vec![ArrayElement::String("any".to_string())]);
                    state = RuleParserState::SourcePort;
                }
                RuleParserEvent::SourcePort(src_port) => {
                    assert_eq!(state, RuleParserState::SourcePort);
                    assert_eq!(src_port, vec![ArrayElement::String("any".to_string())]);
                    state = RuleParserState::Direction;
                }
                RuleParserEvent::Direction(direction) => {
                    assert_eq!(state, RuleParserState::Direction);
                    assert_eq!(direction, Direction::Single);
                    state = RuleParserState::DestIp;
                }
                RuleParserEvent::DestIp(dest_ip) => {
                    assert_eq!(state, RuleParserState::DestIp);
                    assert_eq!(dest_ip, vec![ArrayElement::String("any".to_string())]);
                    state = RuleParserState::DestPort;
                }
                RuleParserEvent::DestPort(dest_port) => {
                    assert_eq!(state, RuleParserState::DestPort);
                    assert_eq!(dest_port, vec![ArrayElement::String("any".to_string())]);
                    state = RuleParserState::StartOfOptions;
                }
                RuleParserEvent::StartOfOptions => {
                    assert_eq!(state, RuleParserState::StartOfOptions);
                    state = RuleParserState::Options;
                }
                _ => {
                    break;
                }
            }
        }
    }
}
