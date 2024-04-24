// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal utilities for loading rules from files and readers.

use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::Path,
};

/// A wraper over a reader providing support for reading multi-line
/// rules as well as tracking the line number.
pub struct Loader {
    /// The path of the file being read. May be None if loader was
    /// created from a reader.
    pub path: Option<String>,
    /// Last line number read. First line is 1.
    pub lineno: usize,
    /// The reader.
    reader: Box<dyn BufRead + 'static>,
}

impl Loader {
    /// Read the next line from the file taking care of multi-line
    /// rules.
    pub fn next_line(&mut self) -> Result<Option<String>, std::io::Error> {
        let mut buf = String::new();
        for line in self.reader.by_ref().lines() {
            self.lineno += 1;
            let line = line?;
            if !line.trim().ends_with('\\') {
                if buf.is_empty() {
                    return Ok(Some(line));
                } else {
                    buf.push_str(&line);
                    return Ok(Some(buf));
                }
            } else {
                buf.push_str(&line[0..line.len() - 1]);
            }
        }
        Ok(None)
    }
}

/// Create a loader from a filename.
pub fn from_filename<P: AsRef<Path>>(path: P) -> Result<Loader, std::io::Error> {
    let path: &Path = path.as_ref();
    let file = File::open(path)?;
    Ok(from_reader(file, Some(path.display().to_string())))
}

/// Create a loader from a reader.
pub fn from_reader<R: Read + 'static>(reader: R, path: Option<String>) -> Loader {
    Loader {
        path,
        reader: Box::new(BufReader::new(reader)),
        lineno: 0,
    }
}
