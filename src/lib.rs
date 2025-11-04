// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal Suricata rule parser/lexer.
//!
//! This library provides a simple scanner for tokenizing Suricata rules into their
//! component parts (headers and options) without attempting to parse option values
//! in detail.

use nom::Offset;

use parsers::ParseError;

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
    pub(crate) fn from_nom_error(err: nom::Err<ParseError<&str>>, start: &str, context: &str) -> Self {
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

