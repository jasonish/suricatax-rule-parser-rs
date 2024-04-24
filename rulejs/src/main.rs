// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;

use suricatax_rule_parser::{loader, Parsed};

#[derive(Debug, Parser)]
struct Args {
    /// Quiet mode, only print errors and time.
    #[clap(short, long)]
    quiet: bool,

    /// Abort on rule parse failure.
    #[clap(long)]
    fail: bool,

    /// Strict mode, fail on unknown options.
    #[clap(long)]
    strict: bool,

    /// Filenames to parse, empty for stdin.
    filenames: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let filenames = if args.filenames.is_empty() {
        vec!["-".to_string()]
    } else {
        args.filenames
    };

    let start = std::time::Instant::now();
    let mut count = 0;

    for filename in &filenames {
        let mut loader = if filename == "-" {
            loader::from_reader(std::io::stdin(), Some(filename.to_string()))
        } else {
            loader::from_filename(filename)?
        };

        while let Some(line) = loader.next_line()? {
            let line = line.trim();

            // Skip empty lines.
            if line.is_empty() {
                continue;
            }

            // Remove comment marker.
            let line = line.strip_prefix('#').unwrap_or(line);

            // Minimal check to see if this could be a rule.
            if !possible_rule(line) {
                continue;
            }

            // Finally parse the rule.
            match suricatax_rule_parser::parse_rule(line) {
                Ok(rule) => {
                    if !args.quiet {
                        println!("{}", serde_json::to_string(&rule)?);
                    }

                    if args.strict {
                        for option in rule.options {
                            if option.parsed == Parsed::Unknown {
                                println!("Unknown option: {}:{:?}", option.name, option.value);
                            }
                        }
                    }

                    count += 1;
                }
                Err(e) => {
                    eprintln!("Error parsing rule: {:?} -- {}", e, line);
                    if args.fail {
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    let elapsed = start.elapsed();
    eprintln!("Parsed {} rules in {:?}", count, elapsed);

    Ok(())
}

fn possible_rule(line: &str) -> bool {
    if !line.contains(':') || !line.contains(';') {
        return false;
    }
    line.contains("alert") || line.contains("msg") || line.contains("sid")
}
