#![no_main]

use libfuzzer_sys::fuzz_target;
use suricatax_rule_parser::parser::RuleScanner;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let scanner = RuleScanner::new(s);
        for _ in scanner {
            // Just iterate through the scanner
        }
    }
});
