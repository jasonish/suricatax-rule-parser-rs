// Copyright 2021 Open Information Security Foundation
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
