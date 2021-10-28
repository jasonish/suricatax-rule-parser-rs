use std::env;
use std::fs::File;
use std::io::BufRead;
use suricata_rule_parser;
use suricata_rule_parser::NewRule;

fn main() {
    let filenames: Vec<String> = env::args().skip(1).collect();
    let mut count = 0;
    for filename in &filenames {
        let file: File = File::open(filename).unwrap();
        let reader = std::io::BufReader::new(file).lines();
        for line in reader {
            if let Ok(line) = line {
                if line.starts_with("#") {
                    continue;
                }
                match suricata_rule_parser::parse_rule(&line) {
                    Err(err) => {
                        println!("Failed to parse rule: {:?} -- {}", err, &line);
                    }
                    Ok((_rem, rule)) => {
                        count += 1;
                        let rule: NewRule = rule.into();
                        let encoded = serde_json::to_string(&rule).unwrap();
                        println!("{}", encoded);
                    }
                }
            } else {
                break;
            }
        }
    }
    println!("count: {}", count);
}
