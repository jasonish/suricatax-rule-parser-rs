// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Types for rule options (keywords).

use serde::{Deserialize, Serialize};

use crate::types::*;
use crate::util::is_default;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteJump {
    pub count: usize,
    pub offset: NumberOrReference<i32>,
    #[serde(skip_serializing_if = "is_default")]
    pub relative: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub multiplier: usize,
    #[serde(skip_serializing_if = "is_default")]
    pub endian: Endian,

    // These can be bundled into an enum.
    #[serde(skip_serializing_if = "is_default")]
    pub string: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub hex: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub dec: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub oct: bool,

    #[serde(skip_serializing_if = "is_default")]
    pub align: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub from_beginning: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub from_end: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub post_offset: i64,
    #[serde(skip_serializing_if = "is_default")]
    pub dce: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub bitmask: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ByteTest {
    pub bytes: usize,
    pub negate: bool,
    pub op: Option<ByteTestOperator>,
    pub value: NumberOrReference<u64>,
    pub offset: NumberOrReference<i32>,
    pub relative: bool,
    pub endian: Endian,
    pub string: bool,
    pub dce: bool,
    pub bitmask: u32,
    pub hex: bool,
    pub dec: bool,
    pub oct: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Content {
    pub pattern: String,
    pub negated: bool,
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Flow {
    #[serde(skip_serializing_if = "is_default")]
    pub to_client: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub to_server: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub from_client: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub from_server: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub established: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub not_established: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub stateless: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub only_stream: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub no_stream: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub only_frag: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub no_frag: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flowbits {
    pub command: FlowbitCommand,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsDataAt {
    pub position: IsDataAtPosition,
    #[serde(skip_serializing_if = "is_default")]
    pub negate: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub relative: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub rawbytes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pcre {
    #[serde(skip_serializing_if = "is_default")]
    pub negate: bool,
    pub pattern: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub modifiers: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vars: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub scheme: String,
    pub reference: String,
}
