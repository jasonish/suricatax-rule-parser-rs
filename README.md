# Experimental Suricata Rule Parser in Rust

This is an experimental Suricata rule parser that is trying to represent rules
in a format somewhat like an abstract rule parser. It could remove the low level
details of rule parsing from applications, leaving the application to apply
meaning to structured rule elements.

## Tools

### rjs

`rjs` is an example application that can convert rules to JSON or YAML. This
isn't hard to do once rules are parsed into Rust data structures. Leveraging the
power of Serde, it is easy to convert the rules to JSON or YAML.

Example usage:

```
cargo run -p rjs -- /var/lib/suricata/rules/suricata.rules | jq
```
