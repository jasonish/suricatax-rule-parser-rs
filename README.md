# suricatax-rule-parser

Experimental Rust scanner for Suricata rules.

The crate tokenizes a rule into header fields and raw option events. It does not
try to fully interpret option semantics; applications can layer their own
validation or higher-level parsing on top of the event stream.

## Example

```rust
use suricatax_rule_parser::scanner::{RuleScanEvent, RuleScanner};

fn main() -> Result<(), suricatax_rule_parser::Error> {
    let rule = r#"alert tcp any any -> any any (msg:"TEST"; sid:1;)"#;

    for event in RuleScanner::new(rule) {
        match event? {
            RuleScanEvent::Action(action) => println!("action={action}"),
            RuleScanEvent::Option { name, value } => println!("{name}={value:?}"),
            _ => {}
        }
    }

    Ok(())
}
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
