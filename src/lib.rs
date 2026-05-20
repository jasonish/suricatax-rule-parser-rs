// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal Suricata rule parser/lexer.
//!
//! This library provides a simple scanner for tokenizing Suricata rules into their
//! component parts (headers and options) without attempting to parse option values
//! in detail.

use nom::Offset;

use scanner::ScanError;

pub mod scanner;

/// Rule scanner errors.
///
/// This error type helps hide the details of the internal scanner errors.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Error {
    pub offset: usize,
    pub reason: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "error at offset {}: {}", self.offset, self.reason)
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Create an external error from a nom error.
    pub(crate) fn from_nom_error(
        err: nom::Err<ScanError<&str>>,
        start: &str,
        context: &str,
    ) -> Self {
        match err {
            nom::Err::Incomplete(_) => Error {
                offset: start.len(),
                reason: format!("{context}: incomplete"),
            },
            nom::Err::Failure(err) | nom::Err::Error(err) => {
                let offset = start.offset(err.input);
                Error {
                    offset,
                    reason: format!("{}: {}", context, err.reason),
                }
            }
        }
    }
}
