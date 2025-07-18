// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Datatypes used by rules.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ArrayElement {
    String(String),
    Array(Vec<ArrayElement>),
    Not(Box<ArrayElement>),
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum ByteTestOperator {
    Lt,
    Gt,
    Lte,
    Gte,
    Eq,
    And,
    Or,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    #[default]
    #[serde(rename = "->")]
    Single,
    #[serde(rename = "<>")]
    Both,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Single => "->",
            Self::Both => "<>",
        };
        write!(f, "{}", label)
    }
}

#[derive(Default, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Endian {
    #[default]
    #[serde(rename = "big")]
    Big,
    #[serde(rename = "little")]
    Little,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowbitCommand {
    #[serde(rename = "noalert")]
    NoAlert,
    #[serde(rename = "set")]
    Set,
    #[serde(rename = "isset")]
    IsSet,
    #[serde(rename = "toggle")]
    Toggle,
    #[serde(rename = "unset")]
    Unset,
    #[serde(rename = "isnotset")]
    IsNotSet,
}

impl std::fmt::Display for FlowbitCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsDataAtPosition {
    Position(u64),
    Identifier(String),
}

/// A common type for values that take a name or a number as a value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NumberOrReference<T> {
    Number(T),
    Name(String),
}

impl Default for NumberOrReference<i32> {
    fn default() -> Self {
        NumberOrReference::Number(0)
    }
}

impl ArrayElement {
    #[inline]
    pub fn not_string(string: String) -> Self {
        ArrayElement::Not(Box::new(ArrayElement::String(string)))
    }

    #[inline]
    pub fn not_array(arr: Vec<ArrayElement>) -> Self {
        ArrayElement::Not(Box::new(ArrayElement::Array(arr)))
    }
}