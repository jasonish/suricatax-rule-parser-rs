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

use std::fs::File;
use std::io::BufRead;
use std::io::Lines;
use std::io::Read;
use suricata_rule_parser;

#[derive(clap::Parser)]
struct Opts {
    /// Quiet mode, only errors and a summary will be printed.
    #[clap(short, long)]
    quiet: bool,

    /// List of filenames to parse.
    filenames: Vec<String>,
}

fn main() {
    let opts: Opts = <Opts as clap::Parser>::parse();
    let mut count = 0;
    let start = std::time::Instant::now();

    let inputs = if opts.filenames.is_empty() {
        vec!["-".to_string()]
    } else {
        opts.filenames
    };

    for filename in &inputs {
        if filename == "-" {
            let stdin = std::io::stdin();
            count += process_file(&mut stdin.lock());
        } else {
            let file: File = File::open(filename).unwrap();
            let mut reader = std::io::BufReader::new(file);
            count += process_file(&mut reader);
        }
    }
    let elapsed = start.elapsed();
    eprintln!("Parsed {} rules in {:?}", count, elapsed);
}

fn process_file<T: BufRead + Read>(reader: &mut T) -> usize {
    let mut lines = reader.lines();
    let mut count = 0;
    loop {
        match next_line(&mut lines) {
            Err(err) => {
                eprintln!("io error: {:?}", err);
                break;
            }
            Ok(None) => {
                break;
            }
            Ok(Some(line)) => {
                if line.is_empty() || line.starts_with("#") {
                    continue;
                }
                match suricata_rule_parser::parse_elements(&line) {
                    Err(err) => {
                        eprintln!("Failed to parse rule: {:?} -- {}", err, &line);
                    }
                    Ok((_rem, rule)) => match suricata_rule_parser::reduce_elements(rule) {
                        Ok((_, elements)) => {
                            count += 1;
                            let encoded = serde_json::to_string(&elements).unwrap();
                            println!("{}", encoded);
                        }
                        Err(err) => {
                            eprintln!("Failed to parse rule: {:?} -- {}", err, &line);
                        }
                    },
                }
            }
        }
    }
    count
}

// Helper to read multiline rules from a file.
fn next_line<T: BufRead>(reader: &mut Lines<T>) -> Result<Option<String>, std::io::Error> {
    let mut buffer = String::new();
    for line in reader {
        let line = line?;
        if !line.trim().ends_with('\\') {
            if buffer.is_empty() {
                return Ok(Some(line));
            } else {
                buffer.push_str(&line);
                return Ok(Some(buffer));
            }
        } else {
            buffer.push_str(&line[0..line.len() - 1]);
        }
    }
    Ok(None)
}
