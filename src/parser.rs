// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashSet;

use nom::{character::complete::multispace0, sequence::preceded};

use crate::{
    parsers::{self, ParseError},
    types::{ArrayElement, Direction},
    util, Error, Parsed, RuleOption,
};

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

pub(crate) fn parse_buffer(name: &str) -> Option<Parsed> {
    if BUFFERS.contains(name) {
        Some(Parsed::Buffer(name.to_string()))
    } else {
        None
    }
}

pub(crate) fn parse_modifier(name: &str) -> Option<Parsed> {
    if MODIFIERS.contains(name) {
        Some(Parsed::Modifier(name.to_string()))
    } else {
        None
    }
}

pub(crate) fn parse_transform(name: &str) -> Option<Parsed> {
    if TRANSFORMS.contains(name) {
        Some(Parsed::Transform(name.to_string()))
    } else {
        None
    }
}

/// Parse an option with no value: buffer names, modifiers, etc.
pub(crate) fn parse_option(name: &str) -> Parsed {
    match name {
        "ftpbounce" => Parsed::Ftpbounce,
        "noalert" => Parsed::Noalert,
        "sameip" => Parsed::Sameip,
        "rawbytes" => Parsed::Rawbytes,
        _ => Parsed::Unknown,
    }
}

pub(crate) fn parse_value<'a>(
    name: &'a str,
    value: &'a str,
) -> Result<Parsed, ParseError<&'a str>> {
    let parsed = match name {
        "ack" => Parsed::Ack(parsers::parse_number(value)?.1),
        "app-layer-event" => Parsed::AppLayerEvent(value.to_string()),
        "app-layer-protocol" => Parsed::AppLayerProtocol(value.to_string()),
        "asn1" => Parsed::Asn1(value.to_string()),
        "base64_decode" => Parsed::Base64Decode(value.to_string()),
        "bsize" => Parsed::Bsize(value.to_string()),
        "byte_jump" => Parsed::ByteJump(parsers::byte_jump::parse_byte_jump(value)?.1),
        "byte_extract" => Parsed::ByteExtract(value.to_string()),
        "byte_test" => Parsed::ByteTest(parsers::byte_test::parse_byte_test(value)?.1),
        "classtype" => Parsed::Classtype(value.to_string()),
        "content" => Parsed::Content(parsers::parse_content(value)?.1),
        "dataset" => Parsed::Dataset(value.to_string()),
        "dce_iface" => Parsed::DceIface(value.to_string()),
        "dce_opnum" => Parsed::DceOpnum(parsers::parse_number(value)?.1),
        "dcerpc.iface" => Parsed::DceRpcIface(value.to_string()),
        "dcerpc.opnum" => Parsed::DceRpcOpnum(parsers::parse_number(value)?.1),
        "decode-event" => Parsed::DecodeEvent(value.to_string()),
        "depth" => Parsed::Depth(parsers::parse_number_or_reference(value)?.1),
        "detection_filter" => Parsed::DetectionFilter(value.to_string()),
        "distance" => Parsed::Distance(parsers::parse_number_or_reference(value)?.1),
        "dnp3_func" => Parsed::Dnp3Func(value.to_string()),
        "dnp3_ind" => Parsed::Dnp3Ind(value.to_string()),
        "dns.opcode" => Parsed::DnsOpcode(parsers::parse_number(value)?.1),
        "dsize" => Parsed::Dsize(value.to_string()),
        "fast_pattern" => Parsed::FastPattern(Some(value.to_string())),
        "fileext" => Parsed::Fileext(value.to_string()),
        "flow" => Parsed::Flow(parsers::parse_flow(value)?.1),
        "flow.bytes_toserver" => Parsed::FlowBytesToServer(value.to_string()),
        "flowbits" => Parsed::Flowbits(parsers::parse_flowbits(value)?.1),
        "flowint" => Parsed::Flowint(value.to_string()),
        "id" => Parsed::Id(parsers::parse_number(value)?.1),
        "fragbits" => Parsed::Fragbits(value.to_string()),
        "fragoffset" => Parsed::FragOffset(value.to_string()),
        "icmp_id" => Parsed::IcmpId(parsers::parse_number(value)?.1),
        "icmp_seq" => Parsed::IcmpSeq(parsers::parse_number(value)?.1),
        "icode" => Parsed::Icode(value.to_string()),
        "ipopts" => Parsed::IpOpts(value.to_string()),
        "ip_proto" => Parsed::IpProto(value.to_string()),
        "isdataat" => Parsed::IsDataAt(parsers::parse_isdataat(value)?.1),
        "itype" => Parsed::Itype(value.to_string()),
        "krb5_err_code" => Parsed::Krb5ErrCode(value.to_string()),
        "metadata" => Parsed::Metadata(parsers::metadata(value)?.1),
        "msg" => Parsed::Message(util::strip_quotes(value).to_string()),
        "offset" => Parsed::Offset(parsers::parse_number_or_reference(value)?.1),
        "pcre" => Parsed::Pcre(parsers::parse_pcre(value)?.1),
        "priority" => Parsed::Priority(parsers::parse_number(value)?.1),
        "reference" => Parsed::Reference(parsers::parse_reference(value)?.1),
        "sameip" => Parsed::Sameip,
        "seq" => Parsed::Seq(parsers::parse_number(value)?.1),
        "sid" => Parsed::Sid(parsers::parse_number(value)?.1),
        "rawbytes" => Parsed::Rawbytes,
        "rev" => Parsed::Rev(parsers::parse_number(value)?.1),
        "snmp.version" => Parsed::SnmpVersion(value.to_string()),
        "ssl_state" => Parsed::SslState(value.to_string()),
        "ssl_version" => Parsed::SslVersion(value.to_string()),
        "stream_size" => Parsed::StreamSize(value.to_string()),
        "tag" => Parsed::Tag(value.to_string()),
        "target" => Parsed::Target(value.to_string()),
        "tls.fingerprint" => Parsed::TlsFingerprint(value.to_string()),
        "tls.version" => Parsed::TlsVersion(value.to_string()),
        "tcp.flags" | "flags" => Parsed::TcpFlags(value.to_string()),
        "threshold" => Parsed::Threshold(value.to_string()),
        "tos" => Parsed::Tos(value.to_string()),
        "ttl" => Parsed::Ttl(value.to_string()),
        "uricontent" => Parsed::UriContent(value.to_string()),
        "urilen" => Parsed::Urilen(value.to_string()),
        "window" => Parsed::Window(value.to_string()),
        "within" => Parsed::Within(parsers::parse_number_or_reference(value)?.1),
        "xbits" => Parsed::Xbits(value.to_string()),
        _ => Parsed::Unknown,
    };
    Ok(parsed)
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

#[derive(Debug, PartialEq, Eq)]
pub enum RuleParserEvent {
    Action(String),
    Protocol(String),
    SourceIp(Vec<ArrayElement>),
    SourcePort(Vec<ArrayElement>),
    Direction(Direction),
    DestIp(Vec<ArrayElement>),
    DestPort(Vec<ArrayElement>),
    StartOfOptions,
    Option(RuleOption),
}

pub struct RuleParser<'a> {
    state: RuleParserState,
    buf: &'a str,
    next: &'a str,
}

impl<'a> RuleParser<'a> {
    pub fn new(buf: &'a str) -> Self {
        Self {
            state: RuleParserState::Action,
            buf,
            next: buf,
        }
    }
}

impl<'a> Iterator for RuleParser<'a> {
    type Item = Result<RuleParserEvent, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            RuleParserState::Action => match parsers::take_until_whitespace(self.next) {
                Ok((next, action)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleParserEvent::Action(action.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "action"))),
            },
            RuleParserState::Protocol => match parsers::take_until_whitespace(self.next) {
                Ok((next, proto)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleParserEvent::Protocol(proto.to_string())))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "protocol"))),
            },
            RuleParserState::SourceIp => match parsers::parse_array(self.next) {
                Ok((next, src_ip)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleParserEvent::SourceIp(src_ip)))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "source-ip"))),
            },
            RuleParserState::SourcePort => match parsers::parse_array(self.next) {
                Ok((next, value)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleParserEvent::SourcePort(value)))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "source-port"))),
            },
            RuleParserState::Direction => {
                match preceded(multispace0, parsers::parse_direction)(self.next) {
                    Ok((next, direction)) => {
                        self.state = self.state.next();
                        self.next = next;
                        Some(Ok(RuleParserEvent::Direction(direction)))
                    }
                    Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "direction"))),
                }
            }
            RuleParserState::DestIp => match parsers::parse_array(self.next) {
                Ok((next, v)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleParserEvent::DestIp(v)))
                }
                Err(err) => Some(Err(Error::from_nom_error(err, self.buf, "destination-ip"))),
            },
            RuleParserState::DestPort => match parsers::parse_array(self.next) {
                Ok((next, v)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleParserEvent::DestPort(v)))
                }
                Err(err) => Some(Err(Error::from_nom_error(
                    err,
                    self.buf,
                    "destination-port",
                ))),
            },
            RuleParserState::StartOfOptions => match parsers::start_of_options(self.next) {
                Ok((next, _)) => {
                    self.state = self.state.next();
                    self.next = next;
                    Some(Ok(RuleParserEvent::StartOfOptions))
                }
                Err(err) => Some(Err(Error::from_nom_error(
                    err,
                    self.buf,
                    "start of options",
                ))),
            },
            RuleParserState::Options => {
                if parsers::end_of_options(self.next).is_ok() {
                    return None;
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

                    let parsed = match parse_value(&name.to_lowercase(), value) {
                        Ok(parsed) => parsed,
                        Err(err) => {
                            return Some(Err(Error::from_parse_error(err, self.buf, name)));
                        }
                    };

                    Some(Ok(RuleParserEvent::Option(RuleOption {
                        name: name.to_string(),
                        value: Some(value.to_string()),
                        parsed,
                    })))
                } else {
                    if let Some(parsed) = parse_buffer(&name.to_lowercase()) {
                        return Some(Ok(RuleParserEvent::Option(RuleOption {
                            name: name.to_string(),
                            value: None,
                            parsed,
                        })));
                    }

                    if let Some(parsed) = parse_modifier(&name.to_lowercase()) {
                        return Some(Ok(RuleParserEvent::Option(RuleOption {
                            name: name.to_string(),
                            value: None,
                            parsed,
                        })));
                    }

                    if let Some(parsed) = parse_transform(&name.to_lowercase()) {
                        return Some(Ok(RuleParserEvent::Option(RuleOption {
                            name: name.to_string(),
                            value: None,
                            parsed,
                        })));
                    }

                    Some(Ok(RuleParserEvent::Option(RuleOption {
                        name: name.to_string(),
                        value: None,
                        parsed: parse_option(&name.to_lowercase()),
                    })))
                }
            }
        }
    }
}
