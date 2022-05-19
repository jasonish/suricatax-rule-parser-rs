// Copyright 2021-2022 Jason Ish
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

use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

use crate::util::is_default;
use crate::RuleParseError;

/// A common type for values that take a name or a number as a value.
#[cfg_attr(
    feature = "serde_support",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
pub enum NumberOrName<T> {
    Number(T),
    Name(String),
}

/// Byte jump.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct ByteJump {
    pub count: usize,
    pub offset: ByteJumpOffset,
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

#[cfg_attr(
    feature = "serde_support",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
pub enum ByteJumpOffset {
    Value(i32),
    Name(String),
}

impl Default for ByteJumpOffset {
    fn default() -> Self {
        Self::Value(0)
    }
}

#[cfg_attr(
    feature = "serde_support",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Debug, PartialEq, Clone)]
pub struct ByteTest {
    pub bytes: usize,
    pub op: ByteTestOperator,
    pub value: NumberOrName<u64>,
    pub offset: NumberOrName<i32>,
    pub relative: bool,
    pub endian: Endian,
    pub string: bool,
    pub base: Base,
    pub dce: bool,
    pub bitmask: u32,
}

#[cfg_attr(
    feature = "serde_support",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Debug, PartialEq, Clone)]
pub enum ByteTestOperator {
    Lt,
    Gt,
    Lte,
    Gte,
    Eq,
    And,
    Or,
}

/// Content type.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(PartialEq, Default, Debug, Clone)]
pub struct Content {
    pub pattern: String,

    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub negate: bool,

    // Modifiers that can exist once per content and make sense to pull into the
    // context object.
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub depth: u64,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub distance: Distance,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub endswith: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub fast_pattern: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub nocase: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub offset: u64,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub startswith: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub within: Within,
}

impl Content {
    pub fn new<S: AsRef<str>>(pattern: S) -> Self {
        Self {
            pattern: pattern.as_ref().to_string(),
            ..Default::default()
        }
    }
}

/// Direction rule header element.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum Direction {
    #[cfg_attr(feature = "serde_support", serde(rename = "single"))]
    Single,
    #[cfg_attr(feature = "serde_support", serde(rename = "both"))]
    Both,
}

impl Default for Direction {
    fn default() -> Self {
        Self::Single
    }
}

/// Distance modifier type.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(PartialEq, Default, Debug, Clone)]
pub struct Distance(pub CountOrName);

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(PartialEq, Default, Debug, Clone)]
pub struct FileData;

/// Flowbits.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct Flowbits {
    pub command: FlowbitCommand,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Vec::is_empty")
    )]
    pub names: Vec<String>,
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

/// IsDataAt (isdataat)
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct IsDataAt {
    pub position: u16,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub negate: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub relative: bool,
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub rawbytes: bool,
}

/// Xbits.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct XBits {
    pub command: XbitCommand,
    pub name: String,
    pub track: String,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub expire: Option<u64>,
}

pub type XbitCommand = FlowbitCommand;

/// Within modifier type.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(PartialEq, Default, Debug, Clone)]
pub struct Within(pub CountOrName);

/// Pcre.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct Pcre {
    #[cfg_attr(feature = "serde_support", serde(skip_serializing_if = "is_default"))]
    pub negate: bool,
    pub pattern: String,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "String::is_empty")
    )]
    pub modifiers: String,
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Vec::is_empty")
    )]
    pub vars: Vec<String>,
}

//
// Helper types.
//

/// Helper type for rule options that can accept an i64 or a name as a value.
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum CountOrName {
    #[cfg_attr(feature = "serde_support", serde(rename = "value"))]
    Value(i64),
    #[cfg_attr(feature = "serde_support", serde(rename = "varname"))]
    Var(String),
}

impl Default for CountOrName {
    fn default() -> Self {
        Self::Value(0)
    }
}

//
// Inner types. Only used within other types.
//

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

// TODO: Should be able to serialize with the to_str() impl..
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Clone)]
pub enum Flow {
    #[cfg_attr(feature = "serde_support", serde(rename = "to_client"))]
    ToClient,
    #[cfg_attr(feature = "serde_support", serde(rename = "to_server"))]
    ToServer,
    #[cfg_attr(feature = "serde_support", serde(rename = "from_client"))]
    FromClient,
    #[cfg_attr(feature = "serde_support", serde(rename = "from_server"))]
    FromServer,
    #[cfg_attr(feature = "serde_support", serde(rename = "established"))]
    Established,
    #[cfg_attr(feature = "serde_support", serde(rename = "not_established"))]
    NotEstablished,
    #[cfg_attr(feature = "serde_support", serde(rename = "stateless"))]
    Stateless,
    #[cfg_attr(feature = "serde_support", serde(rename = "only_stream"))]
    OnlyStream,
    #[cfg_attr(feature = "serde_support", serde(rename = "no_stream"))]
    NoStream,
    #[cfg_attr(feature = "serde_support", serde(rename = "only_frag"))]
    OnlyFrag,
    #[cfg_attr(feature = "serde_support", serde(rename = "no_frag"))]
    NoFrag,
}

impl Flow {
    pub fn to_str(&self) -> &str {
        match self {
            Self::ToClient => "to_client",
            Self::ToServer => "to_server",
            Self::FromClient => "from_client",
            Self::FromServer => "from_server",
            Self::Established => "established",
            Self::NotEstablished => "not_established",
            Self::Stateless => "stateless",
            Self::OnlyStream => "only_stream",
            Self::NoStream => "no_stream",
            Self::OnlyFrag => "only_frag",
            Self::NoFrag => "no_frag",
        }
    }
}

impl FromStr for Flow {
    type Err = nom::Err<RuleParseError<&'static str>>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "to_client" => Self::ToClient,
            "to_server" => Self::ToServer,
            "from_client" => Self::FromClient,
            "from_server" => Self::FromServer,
            "established" => Self::Established,
            "not_established" => Self::NotEstablished,
            "stateless" => Self::Stateless,
            "only_stream" => Self::OnlyStream,
            "no_stream" => Self::NoStream,
            "only_frag" => Self::OnlyStream,
            "no_frag" => Self::NoFrag,
            _ => {
                return Err(nom::Err::Error(RuleParseError::UnknownFlowOption(
                    s.to_string(),
                )));
            }
        };
        Ok(v)
    }
}
