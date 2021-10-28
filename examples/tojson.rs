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
use suricata_rule_parser;
use suricata_rule_parser::NewRule;

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
    for filename in &opts.filenames {
        let file: File = File::open(filename).unwrap();
        let reader = std::io::BufReader::new(file).lines();
        for line in reader {
            if let Ok(line) = line {
                if line.starts_with("#") {
                    continue;
                }
                match suricata_rule_parser::parse_rule(&line) {
                    Err(err) => {
                        eprintln!("Failed to parse rule: {:?} -- {}", err, &line);
                    }
                    Ok((_rem, rule)) => {
                        count += 1;
                        let rule: NewRule = rule.into();
                        let encoded = serde_json::to_string(&rule).unwrap();
                        if !opts.quiet {
                            println!("{}", encoded);
                        }
                    }
                }
            } else {
                break;
            }
        }
    }
    let elapsed = start.elapsed();
    eprintln!("Parsed {} rules in {:?}", count, elapsed);
}
