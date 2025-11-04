// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Datatypes used by the rule scanner.

use serde::{Deserialize, Serialize};

/// Direction indicator in a Suricata rule.
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
