// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashSet;

use nom::{character::complete::multispace0, sequence::preceded};
use serde::Serialize;

use crate::{parsers, Error};

static BUFFER_NAMES: &[&str] = &[
    "base64_data",
    "dns.query",
    "dns_query",
    "file.data",
    "http.accept",
    "http.accept_enc",
    "http.accept_lang",
    "http.connection",
    "http.content_len",
    "http.content_type",
    "http.cookie",
    "http.header",
    "http.header.raw",
    "http.header_names",
    "http.host",
    "http.host.raw",
    "http.location",
    "http.method",
    "http.protocol",
    "http.referer",
    "http.request_body",
    "http.request_line",
    "http.response_body",
    "http.response_line",
    "http.response_lines",
    "http.server",
    "http.start",
    "http.stat_code",
    "http.stat_msg",
    "http.uri",
    "http.uri.raw",
    "http.user_agent",
    "ipv6.hdr",
    "ja3.hash",
    "ja3.string",
    "ja3s.hash",
    "pkt_data",
    "ssh.hassh.server",
    "ssh.software",
    "tcp.hdr",
    "tls.cert_fingerprint",
    "tls.cert_issuer",
    "tls.cert_serial",
    "tls.cert_subject",
    "tls.certs",
    "tls.sni",
];

static MODIFIER_NAMES: &[&str] = &[
    "dce_stub_data",
    "endswith",
    "file_data",
    "http_accept",
    "http_accept_enc",
    "http_accept_lang",
    "http_client_body",
    "http_connection",
    "http_content_len",
    "http_content_type",
    "http_cookie",
    "http_header",
    "http_header_names",
    "http_method",
    "http_method",
    "http_protocol",
    "http_raw_header",
    "http_raw_uri",
    "http_referer",
    "http_request_line",
    "http_start",
    "http_stat_code",
    "http_stat_msg",
    "http_user_agent",
    "ja3_hash",
    "prefilter",
    "ssh_proto",
    "ssh_software",
    "tls_cert_expired",
    "tls_cert_fingerprint",
    "tls_cert_issuer",
    "tls_cert_serial",
    "tls_cert_subject",
    "tls_sni",
    "startswith",
    "http_host",
    "http_uri",
    "nocase",
    "fast_pattern",
];

static TRANSFORM_NAMES: &[&str] = &["dotprefix"];

#[rustfmt::skip]
lazy_static::lazy_static! {
    static ref BUFFERS: HashSet<&'static str> = {
	      let set = HashSet::from_iter(BUFFER_NAMES.iter().cloned());
	      set
    };
    
    static ref MODIFIERS: HashSet<&'static str> = {
	      let set = HashSet::from_iter(MODIFIER_NAMES.iter().cloned());
	      set
    };
    
    static ref TRANSFORMS: HashSet<&'static str> = {
	      let set = HashSet::from_iter(TRANSFORM_NAMES.iter().cloned());
	      set
    };
}


#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RuleParserState {
    Action,
    Protocol,
    SourceIp,
    SourcePort,
    Direction,
    DestIp,
    DestPort,
    StartOfOptions,
    Options,
}

impl RuleParserState {
    pub(crate) fn next(&self) -> Self {
        match self {
            RuleParserState::Action => RuleParserState::Protocol,
            RuleParserState::Protocol => RuleParserState::SourceIp,
            RuleParserState::SourceIp => RuleParserState::SourcePort,
            RuleParserState::SourcePort => RuleParserState::Direction,
            RuleParserState::Direction => RuleParserState::DestIp,
            RuleParserState::DestIp => RuleParserState::DestPort,
            RuleParserState::DestPort => RuleParserState::StartOfOptions,
            RuleParserState::StartOfOptions => RuleParserState::Options,
            RuleParserState::Options => RuleParserState::Options,
        }
    }
}



#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleScanEvent {
    Action(String),
    Protocol(String),
    SourceIp(String),
    SourcePort(String),
    Direction(String),
    DestIp(String),
    DestPort(String),
    StartOfOptions(String),
    Option { name: String, value: Option<String> },
    EndOfOptions(String),
}

pub struct RuleScanner<'a> {
    state: RuleParserState,
    buf: &'a str,
    next: &'a str,

    // Should be moved into a state.
    done: bool,
}

impl<'a> RuleScanner<'a> {
    pub fn new(buf: &'a str) -> Self {
        Self {
            state: RuleParserState::Action,
            buf,
            next: buf,
            done: false,
        }
    }
}

impl<'a> Iterator for RuleScanner<'a> {
    type Item = Result<RuleScanEvent, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.state {
            RuleParserState::Action => match parsers::take_until_whitespace(self.next) {
                Ok((next, action)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::Action(action.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "action"))),
            },
            RuleParserState::Protocol => match parsers::take_until_whitespace(self.next) {
                Ok((next, proto)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::Protocol(proto.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "protocol"))),
            },
            RuleParserState::SourceIp => match parsers::scan_array(self.next) {
                Ok((next, src_ip)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::SourceIp(src_ip.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "source-ip"))),
            },
            RuleParserState::SourcePort => match parsers::scan_array(self.next) {
                Ok((next, value)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::SourcePort(value.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "source-port"))),
            },
            RuleParserState::Direction => {
                match preceded(multispace0, parsers::parse_direction)(self.next) {
                    Ok((next, direction)) => {
                        self.state = self.state.next();
                        self.next = next;
                        Some(Ok(RuleScanEvent::Direction(direction.to_string())))
                    }
                    Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "direction"))),
                }
            }
            RuleParserState::DestIp => match parsers::scan_array(self.next) {
                Ok((next, v)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::DestIp(v.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "destination-ip"))),
            },
            RuleParserState::DestPort => match parsers::scan_array(self.next) {
                Ok((next, v)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::DestPort(v.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(
                    err,
                    self.buf,
                    "destination-port",
                ))),
            },
            RuleParserState::StartOfOptions => match parsers::start_of_options(self.next) {
                Ok((next, value)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleScanEvent::StartOfOptions(value.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(
                    err,
                    self.buf,
                    "start of options",
                ))),
            },
            RuleParserState::Options => {
                if let Ok((next, v)) = parsers::end_of_options(self.next) {
                    self.next = next;
                    self.done = true;
                    return Some(Ok(RuleScanEvent::EndOfOptions(v.to_string())));
                }
                let name = match parsers::option_name(self.next) {
                    Ok((rem, name)) => {
                        self.next = rem;
                        name
                    }
                    Err(err) => {
                        return Some(Err(Error::from_nom_error(err, self.buf, "option name")));
                    }
                };
                let sep = match parsers::options_separator(self.next) {
                    Ok((rem, sep)) => {
                        self.next = rem;
                        sep
                    }
                    Err(err) => {
                        return Some(Err(Error::from_nom_error(
                            err,
                            self.buf,
                            "option separator",
                        )));
                    }
                };
                if sep == ':' {
                    let value = match parsers::parse_option_value(self.next) {
                        Ok((rem, value)) => {
                            self.next = rem;
                            value
                        }
                        Err(err) => {
                            return Some(Err(Error::from_nom_error(err, self.buf, "option value")));
                        }
                    };
                    Some(Ok(RuleScanEvent::Option {
                        name: name.to_string(),
                        value: Some(value.to_string()),
                    }))
                } else {
                    Some(Ok(RuleScanEvent::Option {
                        name: name.to_string(),
                        value: None,
                    }))
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rule_scanner() {
        let input =
            r#"alert tcp any any -> any any (msg:"TEST"; content:"|aa bb cc dd|"; nocase; sid:1;)"#;

        let mut scanner = RuleScanner::new(input);

        let action = scanner.next().unwrap().unwrap();
        assert_eq!(action, RuleScanEvent::Action("alert".to_string()));

        let proto = scanner.next().unwrap().unwrap();
        assert_eq!(proto, RuleScanEvent::Protocol("tcp".to_string()));

        let src_ip = scanner.next().unwrap().unwrap();
        assert_eq!(src_ip, RuleScanEvent::SourceIp("any".to_string()));

        let src_port = scanner.next().unwrap().unwrap();
        assert_eq!(src_port, RuleScanEvent::SourcePort("any".to_string()));

        let direction = scanner.next().unwrap().unwrap();
        assert_eq!(direction, RuleScanEvent::Direction("->".to_string()));

        let dest_ip = scanner.next().unwrap().unwrap();
        assert_eq!(dest_ip, RuleScanEvent::DestIp("any".to_string()));

        let dest_port = scanner.next().unwrap().unwrap();
        assert_eq!(dest_port, RuleScanEvent::DestPort("any".to_string()));

        let start_of_options = scanner.next().unwrap().unwrap();
        assert_eq!(
            start_of_options,
            RuleScanEvent::StartOfOptions("(".to_string())
        );

        let option = scanner.next().unwrap().unwrap();
        assert_eq!(
            option,
            RuleScanEvent::Option {
                name: "msg".to_string(),
                value: Some("\"TEST\"".to_string())
            }
        );

        let option = scanner.next().unwrap().unwrap();
        assert_eq!(
            option,
            RuleScanEvent::Option {
                name: "content".to_string(),
                value: Some("\"|aa bb cc dd|\"".to_string())
            }
        );

        let option = scanner.next().unwrap().unwrap();
        assert_eq!(
            option,
            RuleScanEvent::Option {
                name: "nocase".to_string(),
                value: None
            }
        );

        let option = scanner.next().unwrap().unwrap();
        assert_eq!(
            option,
            RuleScanEvent::Option {
                name: "sid".to_string(),
                value: Some("1".to_string())
            }
        );

        let event = scanner.next().unwrap().unwrap();
        assert_eq!(event, RuleScanEvent::EndOfOptions(")".to_string()));

        let event = scanner.next();
        assert_eq!(event, None);
    }
}
