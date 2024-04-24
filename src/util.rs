// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Remove quotes from a string preserving escaped quotes.
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

/// Check if a value is the same as its default.
///
/// Useful for Serde's skip_serializing_if to suppress defaults being output.
pub(crate) fn is_default<T>(val: &T) -> bool
where
    T: Default + PartialEq,
{
    (*val) == Default::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_quotes() {
        assert_eq!(strip_quotes(r#""hello""#), "hello");
        assert_eq!(strip_quotes(r#""hello\"""#), r#"hello""#);
        assert_eq!(strip_quotes(r#""foo"bar"#), "foobar");
    }
}
