#![no_main]

use libfuzzer_sys::fuzz_target;
use suricatax_rule_parser::parse_rule;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_rule(s);
    }
});
