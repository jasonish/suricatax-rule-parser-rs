// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

use nom::Offset;
use serde::{Deserialize, Serialize};

use parsers::{ByteJump, ByteTest, Content, Flow, Flowbits, IsDataAt, Pcre, Reference, ParseError};
use types::{ArrayElement, Direction, NumberOrReference};

pub mod loader;
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


