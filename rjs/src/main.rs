// Copyright 2021 Jason Ish
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

use serde::Serialize;
use std::fs::File;
use std::io::BufRead;
use std::io::Lines;
use std::io::Read;
use suricatax_rule_parser::types::Direction;
use suricatax_rule_parser::Element;

#[derive(clap::Parser)]
struct Opts {
    /// Quiet mode, only errors and a summary will be printed.
    #[clap(short, long)]
    quiet: bool,

    /// Output to YAML instead of JSON.
    #[clap(long)]
    yaml: bool,

    /// Output raw elements instead of a constructed rule.
    #[clap(long)]
    elements: bool,

    /// List of filenames to parse.
    filenames: Vec<String>,
}

/// An idea of what a structured rule could look like.
///
/// This is not part of the parsing library yet as this could be somewhat
/// subjective.
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "snake_case")]
struct Rule {
    // Header.
    action: String,
    protocol: String,
    src_addr: String,
    src_port: String,
    direction: Direction,
    dst_addr: String,
    dst_port: String,

    // Rule options that should only exist once or get aggregated into a single
    // entry.
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classtype: Option<String>,
    signature_id: Option<u64>,
    revision: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reference: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    metadata: Vec<String>,

    #[serde(skip_serializing_if = "is_false")]
    noalert: bool,

    options: Vec<Element>,
}

impl From<Vec<Element>> for Rule {
    fn from(elements: Vec<Element>) -> Rule {
        let mut rule = Rule::default();
        for element in elements {
            match element {
                Element::Action(action) => {
                    rule.action = action;
                }
                Element::Protocol(protocol) => {
                    rule.protocol = protocol;
                }
                Element::SrcAddr(addr) => {
                    rule.src_addr = addr;
                }
                Element::SrcPort(port) => {
                    rule.src_port = port;
                }
                Element::Direction(direction) => {
                    rule.direction = direction;
                }
                Element::DstAddr(addr) => {
                    rule.dst_addr = addr;
                }
                Element::DstPort(port) => {
                    rule.dst_port = port;
                }
                Element::Message(message) => {
                    rule.message = Some(message);
                }
                Element::Classtype(classtype) => {
                    rule.classtype = Some(classtype);
                }
                Element::Sid(sid) => {
                    rule.signature_id = Some(sid);
                }
                Element::Rev(rev) => {
                    rule.revision = rev;
                }
                Element::Reference(reference) => {
                    rule.reference.push(reference);
                }
                Element::Metadata(mut metadata) => {
                    if rule.metadata.is_empty() {
                        rule.metadata = metadata;
                    } else {
                        rule.metadata.append(&mut metadata);
                    }
                }
                Element::NoAlert(_) => {
                    rule.noalert = true;
                }
                _ => {
                    rule.options.push(element);
                }
            }
        }
        rule
    }
}

fn main() {
    let opts: Opts = <Opts as clap::Parser>::parse();
    let mut count = 0;
    let start = std::time::Instant::now();

    let inputs = if opts.filenames.is_empty() {
        vec!["-".to_string()]
    } else {
        opts.filenames.clone()
    };

    for filename in &inputs {
        if filename == "-" {
            let stdin = std::io::stdin();
            count += process_file(&mut stdin.lock(), &opts);
        } else {
            let file: File = File::open(filename).unwrap();
            let mut reader = std::io::BufReader::new(file);
            count += process_file(&mut reader, &opts);
        }
    }
    let elapsed = start.elapsed();
    eprintln!("Parsed {} rules in {:?}", count, elapsed);
}

fn process_file<T: BufRead + Read>(reader: &mut T, opts: &Opts) -> usize {
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
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                match suricatax_rule_parser::parse_elements(&line) {
                    Err(err) => {
                        eprintln!("Failed to parse rule: {:?} -- {}", err, &line);
                    }
                    Ok((_rem, rule)) => match suricatax_rule_parser::reduce_elements(rule) {
                        Ok((_, elements)) => {
                            count += 1;
                            if opts.elements && !opts.quiet {
                                let encoded = if opts.yaml {
                                    serde_yaml::to_string(&elements).unwrap()
                                } else {
                                    serde_json::to_string(&elements).unwrap()
                                };
                                if !opts.quiet {
                                    println!("{}", encoded);
                                }
                            } else if !opts.elements {
                                let rule = Rule::from(elements);
                                if !opts.quiet {
                                    let encoded = if opts.yaml {
                                        serde_yaml::to_string(&rule).unwrap()
                                    } else {
                                        serde_json::to_string(&rule).unwrap()
                                    };
                                    println!("{}", encoded);
                                }
                            }
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

fn is_false(v: &bool) -> bool {
    *v == false
}
