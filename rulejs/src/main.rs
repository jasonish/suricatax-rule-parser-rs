// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;

use serde::Serialize;
use suricatax_rule_parser::{
    loader,
    parser::{RuleScanEvent, RuleScanner},
};

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

#[derive(Default, Debug, Serialize)]
struct PrettyRule {
    action: String,
    proto: String,
    src_ip: String,
    src_port: String,
    direction: String,
    dest_ip: String,
    dest_port: String,
    option: Vec<PrettyRuleOption>,
}

#[derive(Default, Debug, Serialize)]
struct PrettyRuleOption {
    name: String,
    value: Option<String>,
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

            let scanner = RuleScanner::new(line);
            let mut rule = PrettyRule::default();
            for event in scanner {
                match event {
                    Ok(event) => match event {
                        RuleScanEvent::Action(action) => {
                            rule.action = action.to_string();
                        }
                        RuleScanEvent::Protocol(proto) => {
                            rule.proto = proto.to_string();
                        }
                        RuleScanEvent::SourceIp(src_ip) => {
                            rule.src_ip = src_ip.to_string();
                        }
                        RuleScanEvent::SourcePort(dest_ip) => {
                            rule.src_port = dest_ip.to_string();
                        }
                        RuleScanEvent::Direction(dir) => {
                            rule.direction = dir.to_string();
                        }
                        RuleScanEvent::DestIp(ip) => {
                            rule.dest_ip = ip.to_string();
                        }
                        RuleScanEvent::DestPort(port) => {
                            rule.dest_port = port.to_string();
                        }
                        RuleScanEvent::StartOfOptions(_) => {}
                        RuleScanEvent::Option { name, value } => {
                            rule.option.push(PrettyRuleOption { name, value });
                        }
                        RuleScanEvent::EndOfOptions(_) => {}
                    },
                    Err(e) => {
                        eprintln!("Error scanning rule: {:?} -- {}", e, line);
                        if args.fail {
                            std::process::exit(1);
                        }
                    }
                }
            }
            println!("{}", serde_json::to_string(&rule)?);
            count += 1;
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
