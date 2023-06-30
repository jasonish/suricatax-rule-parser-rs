// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Check if a value is the same as its default.
///
/// Useful for Serde's skip_serializing_if to suppress defaults being output.
pub fn is_default<T>(val: &T) -> bool
where
    T: Default + PartialEq,
{
    (*val) == Default::default()
}

/// Remove quotes from a string, but preserve any escaped quotes.
pub(crate) fn strip_quotes(input: &str) -> String {
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
