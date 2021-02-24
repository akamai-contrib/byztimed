//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//!Network Time Security Key Establishment (NTS-KE)
//!
//!See <https://datatracker.ietf.org/doc/draft-ietf-ntp-using-nts-for-ntp/>.
//! Byztime key exchange works exactly like NTP key exchange, aside
//! from using a different next-protocol codepoint and a different
//! record type for sending cookies.

//The original version of this module was lightly cribbed from
// <https://github.com/wbl/nts-rust>. It's since been completely
// rewritten and probably can't still be considered a derived work;
// however, for legal prudence the following notice should be
// retained:
//
//  Copyright 2019 Cloudflare
//  Permission to use, copy, modify, and/or distribute this software for
//  any purpose with or without fee is hereby granted, provided that the
//  above copyright notice and this permission notice appear in all
//  copies.

use crate::aead::*;
use crate::cookie::{seal_cookie, CookieData};
use log::{debug, trace};
use rand::thread_rng;
use std::iter::FromIterator;
use tokio::io;
use tokio::prelude::*;
use tokio_rustls::rustls::Session;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};
#[cfg(test)]
use rand::{Rng, SeedableRng};

//Various enumerations and constants defined in the NTS-KE spec.

///An NTS-KE [Record Type](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-7.6) number
#[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct NtskeRecordNumber(pub u16);

#[cfg(test)]
impl Arbitrary for NtskeRecordNumber {
    fn arbitrary<G: Gen>(g: &mut G) -> NtskeRecordNumber {
        NtskeRecordNumber(u16::arbitrary(g) & 0x7fff)
    }
}

///An NTS-KE [Error](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-7.8) number
#[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct NtskeError(pub u16);

#[cfg(test)]
impl Arbitrary for NtskeError {
    fn arbitrary<G: Gen>(g: &mut G) -> NtskeError {
        NtskeError(u16::arbitrary(g))
    }
}

///An NTS-KE [Warning](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-7.8) number
#[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct NtskeWarning(pub u16);

#[cfg(test)]
impl Arbitrary for NtskeWarning {
    fn arbitrary<G: Gen>(g: &mut G) -> NtskeWarning {
        NtskeWarning(u16::arbitrary(g))
    }
}

///An NTS [Next Protocol](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-7.7) number
#[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct NtsNextProtocol(pub u16);

#[cfg(test)]
impl Arbitrary for NtsNextProtocol {
    fn arbitrary<G: Gen>(g: &mut G) -> NtsNextProtocol {
        NtsNextProtocol(u16::arbitrary(g))
    }
}

///An RFC 5116 [AEAD algorithm](https://tools.ietf.org/html/rfc5116#section-6) number
#[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct AeadAlgorithm(pub u16);

#[cfg(test)]
impl Arbitrary for AeadAlgorithm {
    fn arbitrary<G: Gen>(g: &mut G) -> AeadAlgorithm {
        AeadAlgorithm(u16::arbitrary(g))
    }
}

pub const RECORD_NUMBER_END_OF_MESSAGE: NtskeRecordNumber = NtskeRecordNumber(0);
pub const RECORD_NUMBER_NEXT_PROTOCOL_NEGOTIATION: NtskeRecordNumber = NtskeRecordNumber(1);
pub const RECORD_NUMBER_ERROR: NtskeRecordNumber = NtskeRecordNumber(2);
pub const RECORD_NUMBER_WARNING: NtskeRecordNumber = NtskeRecordNumber(3);
pub const RECORD_NUMBER_AEAD_ALGORITHM_NEGOTIATION: NtskeRecordNumber = NtskeRecordNumber(4);
///Taken from private & experimental use range. ASCII "BZ".
pub const RECORD_NUMBER_NEW_COOKIE_FOR_BYZTIME: NtskeRecordNumber = NtskeRecordNumber(0x425a);

pub const ERROR_UNRECOGNIZED_CRITICAL_RECORD: NtskeError = NtskeError(0);
pub const ERROR_BAD_REQUEST: NtskeError = NtskeError(1);

///Taken from private & experimental use range. Lower 15 bits are ASCII "BZ".
pub const NTS_NEXT_PROTOCOL_BYZTIME: NtsNextProtocol = NtsNextProtocol(0xc25a);

//These are the five currently-registered AEAD algorithms that are
// sane to use with NTS. We actually only support the first one, but
// might add AES-GCM-SIV support later.
pub const AEAD_ALGORITHM_AES_SIV_CMAC_256: AeadAlgorithm = AeadAlgorithm(15);
pub const AEAD_ALGORITHM_AES_SIV_CMAC_384: AeadAlgorithm = AeadAlgorithm(16);
pub const AEAD_ALGORITHM_AES_SIV_CMAC_512: AeadAlgorithm = AeadAlgorithm(17);
pub const AEAD_ALGORITHM_AES_128_GCM_SIV: AeadAlgorithm = AeadAlgorithm(30);
pub const AEAD_ALGORITHM_AES_256_GCM_SIV: AeadAlgorithm = AeadAlgorithm(31);

///[ALPN protocol ID](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-7.2) for NTS-KE
pub const NTSKE_ALPN: &[u8] = b"ntske/1";

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
///Representation of an [NTS-KE record](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-4)
pub enum NtskeRecord {
    ///[End of message](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-4.1.1) record
    EndOfMessage,
    ///[NTS Next Protocol Negotiation](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-4.1.2) record
    NextProtocolNegotiation(Vec<NtsNextProtocol>),
    ///[Error](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-4.1.3) record
    Error(NtskeError),
    ///[Warning](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-4.1.4) record
    Warning(NtskeWarning),
    ///[AEAD Algorithm Negotiation](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-4.1.5) record
    AeadAlgorithmNegotiation(Vec<AeadAlgorithm>),
    ///New Cookie for Byztime record. Perfectly analogous to the [New Cookie for NTPv4](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-20#section-4.1.6) record, but for Byztime instead
    NewCookieForByztime(Vec<u8>),
    ///Raw representation of any unrecognized record. Gives critical bit, record type, and body
    UnrecognizedRecord(bool, NtskeRecordNumber, Vec<u8>),
}

#[cfg(test)]
impl Arbitrary for NtskeRecord {
    fn arbitrary<G: Gen>(g: &mut G) -> NtskeRecord {
        use NtskeRecord::*;
        match g.gen_range(0, 7) {
            0 => EndOfMessage,
            1 => NextProtocolNegotiation(Vec::<NtsNextProtocol>::arbitrary(g)),
            2 => Error(NtskeError::arbitrary(g)),
            3 => Warning(NtskeWarning::arbitrary(g)),
            4 => AeadAlgorithmNegotiation(Vec::<AeadAlgorithm>::arbitrary(g)),
            5 => NewCookieForByztime(Vec::<u8>::arbitrary(g)),
            _ => UnrecognizedRecord(
                bool::arbitrary(g),
                NtskeRecordNumber(g.gen_range(6, 0x425a)),
                Vec::<u8>::arbitrary(g),
            ),
        }
    }
}

///An enumeration of everything that can be wrong about an NTS-KE
/// response.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NtskeProblem {
    ///The response was an error response
    ErrorResponse(NtskeError),
    ///The response contained a warning, which we treat as fatal
    WarningResponse(NtskeWarning),
    ///We couldn't negotiate a next protocol
    NextProtocolNegotiationFailed,
    ///We couldn't negotiate an AEAD algorithm
    AeadAlgorithmNegotiationFailed,
    ///The response was syntactically invalid
    BadResponse,
    ///The response contained an unrecognized record type with its critical bit set
    UnrecognizedCriticalRecord(NtskeRecordNumber),
}

///Parse a string of big-endian 16-bit unsigned integers.
fn parse_be_u16_vec(buf: &[u8]) -> Option<Vec<u16>> {
    if buf.len() & 1 == 1 {
        return None;
    }
    let mut bufptr = buf;
    let mut out: Vec<u16> = Vec::with_capacity(buf.len() >> 1);
    while !bufptr.is_empty() {
        out.push(u16::from_be_bytes([bufptr[0], bufptr[1]]));
        bufptr = &bufptr[2..];
    }
    Some(out)
}

impl NtskeRecord {
    ///Parse an NTS-KE record. `head` is the first four
    ///bytes of the record (containing record type and body length)
    ///`body is the rest.
    fn parse(head: &[u8], body: &[u8]) -> NtskeRecord {
        assert!(head.len() == 4);
        let crit_num = u16::from_be_bytes([head[0], head[1]]);
        let crit = crit_num & (1 << 15) != 0;
        let rec_num = NtskeRecordNumber(crit_num & 0x7fff);
        let body_len = u16::from_be_bytes([head[2], head[3]]);
        assert!(body_len as usize == body.len());

        match rec_num {
            RECORD_NUMBER_END_OF_MESSAGE => {
                if body_len > 0 {
                    NtskeRecord::UnrecognizedRecord(crit, rec_num, body.to_vec())
                } else {
                    NtskeRecord::EndOfMessage
                }
            }
            RECORD_NUMBER_NEXT_PROTOCOL_NEGOTIATION => match parse_be_u16_vec(body) {
                None => NtskeRecord::UnrecognizedRecord(crit, rec_num, body.to_vec()),
                Some(protos) => NtskeRecord::NextProtocolNegotiation(Vec::from_iter(
                    protos.into_iter().map(NtsNextProtocol),
                )),
            },
            RECORD_NUMBER_ERROR => {
                if body_len != 2 {
                    NtskeRecord::UnrecognizedRecord(crit, rec_num, body.to_vec())
                } else {
                    NtskeRecord::Error(NtskeError(u16::from_be_bytes([body[0], body[1]])))
                }
            }
            RECORD_NUMBER_WARNING => {
                if body_len != 2 {
                    NtskeRecord::UnrecognizedRecord(crit, rec_num, body.to_vec())
                } else {
                    NtskeRecord::Warning(NtskeWarning(u16::from_be_bytes([body[0], body[1]])))
                }
            }
            RECORD_NUMBER_AEAD_ALGORITHM_NEGOTIATION => match parse_be_u16_vec(body) {
                None => NtskeRecord::UnrecognizedRecord(crit, rec_num, body.to_vec()),
                Some(protos) => NtskeRecord::AeadAlgorithmNegotiation(Vec::from_iter(
                    protos.into_iter().map(AeadAlgorithm),
                )),
            },
            RECORD_NUMBER_NEW_COOKIE_FOR_BYZTIME => NtskeRecord::NewCookieForByztime(body.to_vec()),
            _ => NtskeRecord::UnrecognizedRecord(crit, rec_num, body.to_vec()),
        }
    }

    ///Returns the record number indicating the type of this record.
    fn record_number(&self) -> NtskeRecordNumber {
        use NtskeRecord::*;
        match self {
            EndOfMessage => RECORD_NUMBER_END_OF_MESSAGE,
            NextProtocolNegotiation(_) => RECORD_NUMBER_NEXT_PROTOCOL_NEGOTIATION,
            Error(_) => RECORD_NUMBER_ERROR,
            Warning(_) => RECORD_NUMBER_WARNING,
            AeadAlgorithmNegotiation(_) => RECORD_NUMBER_AEAD_ALGORITHM_NEGOTIATION,
            NewCookieForByztime(_) => RECORD_NUMBER_NEW_COOKIE_FOR_BYZTIME,
            UnrecognizedRecord(_, n, _) => NtskeRecordNumber(n.0),
        }
    }

    ///Return whether this record is critical, i.e., whether the receiver should
    /// treat it as an error if it's not understood rather than ignoring it.
    /// The argument allows for some records to have different criticality depending
    /// on whether they're in a request or a response, but we don't actually have
    /// any cases where we discriminate.
    fn is_critical(&self, _is_response: bool) -> bool {
        use NtskeRecord::*;
        match self {
            EndOfMessage => true,
            NextProtocolNegotiation(_) => true,
            Error(_) => true,
            Warning(_) => true,
            AeadAlgorithmNegotiation(_) => true,
            NewCookieForByztime(_) => false,
            UnrecognizedRecord(c, _, _) => *c,
        }
    }

    ///Returns how long this record's body will be when serialized.
    fn body_length(&self) -> usize {
        use NtskeRecord::*;
        match self {
            EndOfMessage => 0,
            NextProtocolNegotiation(protos) => 2 * protos.len(),
            Error(_) => 2,
            Warning(_) => 2,
            AeadAlgorithmNegotiation(algs) => 2 * algs.len(),
            NewCookieForByztime(cookie) => cookie.len(),
            UnrecognizedRecord(_, _, v) => v.len(),
        }
    }

    ///Extend `v` with a serialized representation of this record.
    fn extend(&self, v: &mut Vec<u8>, as_response: bool) {
        let body_len = self.body_length();
        assert!(body_len <= u16::max_value() as usize);

        //First two bytes of the serialized record: record type and critical bit
        let crit_and_type = if self.is_critical(as_response) {
            (1 << 15 as u16) | self.record_number().0
        } else {
            self.record_number().0
        };

        let old_len = v.len(); //Just for debugging so we can check the assertion at the bottom
        v.extend_from_slice(&crit_and_type.to_be_bytes()); //Write the record type and critical bit
        v.extend_from_slice(&(body_len as u16).to_be_bytes()); //Write the body length

        //Write the body
        match self {
            NtskeRecord::EndOfMessage => {}
            NtskeRecord::NextProtocolNegotiation(protos) => {
                for proto in protos {
                    v.extend_from_slice(&proto.0.to_be_bytes());
                }
            }
            NtskeRecord::Error(error) => {
                v.extend_from_slice(&error.0.to_be_bytes());
            }
            NtskeRecord::Warning(warning) => {
                v.extend_from_slice(&warning.0.to_be_bytes());
            }
            NtskeRecord::AeadAlgorithmNegotiation(algs) => {
                for alg in algs {
                    v.extend_from_slice(&alg.0.to_be_bytes());
                }
            }
            NtskeRecord::NewCookieForByztime(cookie) => {
                v.extend_from_slice(cookie.as_slice());
            }
            NtskeRecord::UnrecognizedRecord(_, _, body) => {
                v.extend_from_slice(body.as_slice());
            }
        };

        debug_assert!(v.len() == old_len + body_len + 4);
    }
}

///Asynchronously serialize and write `records` to `stream`.
async fn write_records_async<A: io::AsyncWrite + std::marker::Unpin>(
    stream: &mut A,
    records: &[NtskeRecord],
    as_response: bool,
) -> io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    for record in records {
        record.extend(&mut buf, as_response);
    }

    stream.write_all(&buf).await?;
    Ok(())
}

///Asynchronously read and parse NTS-KE records from `stream`.
async fn read_records_async<A: io::AsyncRead + std::marker::Unpin>(
    stream: &mut A,
) -> io::Result<Vec<NtskeRecord>> {
    let mut records = Vec::<NtskeRecord>::new();
    loop {
        let mut head = [0; 4];
        stream.read_exact(&mut head).await?;
        let body_len = u16::from_be_bytes([head[2], head[3]]) as usize;
        let mut body = vec![0; body_len];
        stream.read_exact(&mut body).await?;
        let record = NtskeRecord::parse(&head, &body.as_slice());
        match record {
            NtskeRecord::EndOfMessage => {
                records.push(record);
                return Ok(records);
            }
            _ => records.push(record),
        }
    }
}

fn make_ntske_request() -> Vec<NtskeRecord> {
    vec![
        NtskeRecord::NextProtocolNegotiation(vec![NTS_NEXT_PROTOCOL_BYZTIME]),
        NtskeRecord::AeadAlgorithmNegotiation(vec![AEAD_ALGORITHM_AES_SIV_CMAC_256]),
        NtskeRecord::EndOfMessage,
    ]
}

fn make_ntske_error_response(error: NtskeError) -> Vec<NtskeRecord> {
    vec![NtskeRecord::Error(error), NtskeRecord::EndOfMessage]
}

///Construct a response appropriate to a given NTS-KE request.
fn respond_to_ntske_request(
    request: &[NtskeRecord],
    master_key: &Aes128SivKey,
    master_key_id: u32,
    c2s: &Aes128SivKey,
    s2c: &Aes128SivKey,
) -> Vec<NtskeRecord> {
    let mut next_protocol_response = Vec::<NtsNextProtocol>::with_capacity(1); //Will contain at most just NTS_NEXT_PROTOCOL_BYZTIME
    let mut aead_response = Vec::<AeadAlgorithm>::with_capacity(1); //Will contain at most just AEAD_ALGORITHM_AES_SIV_CMAC_256
    let mut response = Vec::<NtskeRecord>::with_capacity(11); //Will contain 1 next protocol + 1 aead + 8 cookies + 1 end of message = 11 records

    let mut next_protocol_seen = false; //Set when we've encountered a Next Protocol Negotiation record
    let mut next_protocol_ok = false; //Set if the NPN record contained the value we expected (Byztime)
    let mut aead_seen = false; //Set when we've encountered an AEAD Algorithm negotiation record
    let mut aead_ok = false; //Set if the AEAD record contained the cipher we support (AES-128-SIV)
    let mut rng = thread_rng();

    for record in request {
        match record {
            NtskeRecord::EndOfMessage => break,
            NtskeRecord::NextProtocolNegotiation(next_protos) => {
                if next_protocol_seen {
                    return make_ntske_error_response(ERROR_BAD_REQUEST);
                }
                next_protocol_seen = true;
                if next_protos.contains(&NTS_NEXT_PROTOCOL_BYZTIME) {
                    next_protocol_ok = true;
                    next_protocol_response.push(NTS_NEXT_PROTOCOL_BYZTIME);
                }
            }
            NtskeRecord::Error(_) => return make_ntske_error_response(ERROR_BAD_REQUEST),
            NtskeRecord::Warning(_) => return make_ntske_error_response(ERROR_BAD_REQUEST),
            NtskeRecord::AeadAlgorithmNegotiation(algos) => {
                if aead_seen {
                    return make_ntske_error_response(ERROR_BAD_REQUEST);
                }
                aead_seen = true;
                if algos.contains(&AEAD_ALGORITHM_AES_SIV_CMAC_256) {
                    aead_ok = true;
                    aead_response.push(AEAD_ALGORITHM_AES_SIV_CMAC_256);
                }
            }
            NtskeRecord::NewCookieForByztime(_) => {
                return make_ntske_error_response(ERROR_BAD_REQUEST)
            }
            NtskeRecord::UnrecognizedRecord(critical, _, _) => {
                if *critical {
                    return make_ntske_error_response(ERROR_UNRECOGNIZED_CRITICAL_RECORD);
                }
            }
        }
    }

    if next_protocol_seen {
        response.push(NtskeRecord::NextProtocolNegotiation(next_protocol_response));
    }

    if aead_seen {
        response.push(NtskeRecord::AeadAlgorithmNegotiation(aead_response));
    }

    if !next_protocol_ok || !aead_ok {
        response.push(NtskeRecord::EndOfMessage);
        return response;
    }

    for _ in 0..8 {
        let cookie_data = CookieData {
            c2s: *c2s,
            s2c: *s2c,
        };
        let cookie = seal_cookie(&cookie_data, master_key, master_key_id, &mut rng);
        response.push(NtskeRecord::NewCookieForByztime(cookie));
    }

    response.push(NtskeRecord::EndOfMessage);
    response
}

///Determine whether an NTS-KE response is well-formed and whether it
/// communicates success or failure. If successful, return the
/// provided cookies.
fn interpret_ntske_response(response: Vec<NtskeRecord>) -> Result<Vec<Vec<u8>>, NtskeProblem> {
    let mut next_protocol_seen = false;
    let mut next_protocol_ok = false;
    let mut aead_seen = false;
    let mut aead_ok = false;
    let mut cookies = Vec::with_capacity(8);

    for record in response {
        match record {
            NtskeRecord::EndOfMessage => break,
            NtskeRecord::NextProtocolNegotiation(next_protos) => {
                if next_protocol_seen {
                    return Err(NtskeProblem::BadResponse);
                }
                next_protocol_seen = true;
                if next_protos.contains(&NTS_NEXT_PROTOCOL_BYZTIME) {
                    next_protocol_ok = true;
                }
            }
            NtskeRecord::Error(e) => return Err(NtskeProblem::ErrorResponse(e)),
            NtskeRecord::Warning(w) => return Err(NtskeProblem::WarningResponse(w)),
            NtskeRecord::AeadAlgorithmNegotiation(algos) => {
                if aead_seen {
                    return Err(NtskeProblem::BadResponse);
                }
                aead_seen = true;
                if algos.contains(&AEAD_ALGORITHM_AES_SIV_CMAC_256) {
                    aead_ok = true;
                }
            }
            NtskeRecord::NewCookieForByztime(cookie) => {
                cookies.push(cookie);
            }
            NtskeRecord::UnrecognizedRecord(critical, num, _) => {
                if critical {
                    return Err(NtskeProblem::UnrecognizedCriticalRecord(num));
                }
            }
        }
    }

    if !next_protocol_ok {
        return Err(NtskeProblem::NextProtocolNegotiationFailed);
    }

    if !aead_ok {
        return Err(NtskeProblem::AeadAlgorithmNegotiationFailed);
    }

    Ok(cookies)
}

///Extract Byztime C2S and S2C keys from a TLS session.
fn extract_session_keys<S: Session>(session: &S) -> (Aes128SivKey, Aes128SivKey) {
    const RFC5705_LABEL: &[u8] = b"EXPORTER-network-time-security/1";
    //First four bytes are constructed as required by the NTS spec.
    // Last byte is protocol-specific but we use the same two key
    // types as NTP (C2S and S2C) and the same constants (0 and 1) to
    // identify them.
    const RFC5705_CONTEXT_C2S: &[u8] = &[
        (NTS_NEXT_PROTOCOL_BYZTIME.0 >> 8) as u8,
        (NTS_NEXT_PROTOCOL_BYZTIME.0 & 0xff) as u8,
        (AEAD_ALGORITHM_AES_SIV_CMAC_256.0 >> 8) as u8,
        (AEAD_ALGORITHM_AES_SIV_CMAC_256.0 & 0xff) as u8,
        0,
    ];
    const RFC5705_CONTEXT_S2C: &[u8] = &[
        (NTS_NEXT_PROTOCOL_BYZTIME.0 >> 8) as u8,
        (NTS_NEXT_PROTOCOL_BYZTIME.0 & 0xff) as u8,
        (AEAD_ALGORITHM_AES_SIV_CMAC_256.0 >> 8) as u8,
        (AEAD_ALGORITHM_AES_SIV_CMAC_256.0 & 0xff) as u8,
        1,
    ];

    //The only time these calls should ever fail is if the requested
    // amount of key material is greater than what the KDF supports.
    let mut c2s = Aes128SivKey::from([0; 32]);
    session
        .export_keying_material(c2s.as_mut_slice(), RFC5705_LABEL, Some(RFC5705_CONTEXT_C2S))
        .expect("Error extracting C2S key from TLS session");
    let mut s2c = Aes128SivKey::from([0; 32]);
    session
        .export_keying_material(s2c.as_mut_slice(), RFC5705_LABEL, Some(RFC5705_CONTEXT_S2C))
        .expect("Error extracting S2C key from TLS session");
    (c2s, s2c)
}

///Run the NTS-KE protocol as a server
///
///Reads an NTS-KE request from `stream` and then writes back a response,
/// using `master_key` to encrypt the cookies it sends.
pub async fn serve_ntske(
    master_key: Aes128SivKey,
    master_key_id: u32,
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> io::Result<()> {
    let request = read_records_async(stream).await?;
    let (socket, session) = stream.get_ref();
    let peer_addr = socket.peer_addr()?;
    let (c2s, s2c) = extract_session_keys(session);
    debug!("Got NTS-KE request from {}", peer_addr);
    trace!("NTS-KE request body: {:?}", request);
    let response = respond_to_ntske_request(&request, &master_key, master_key_id, &c2s, &s2c);
    debug!("Sending NTS-KE response to {}", peer_addr);
    trace!("Sending NTS-KE response body: {:?}", response);
    write_records_async(stream, &response, true).await?;
    Ok(())
}

///The relevant output of a successful NTS-KE run.
pub struct NtskeOutput {
    ///The cookies returned by the server
    pub cookies: Vec<Vec<u8>>,
    ///C2S key extracted from the session
    pub c2s: Aes128SivKey,
    ///S2C key extracted from the session
    pub s2c: Aes128SivKey,
}

///Run the NTS-KE protocol as a client
///
///Writes an NTS-KE request to `stream` and then reads and interprets the response.
pub async fn request_ntske(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> io::Result<Result<NtskeOutput, NtskeProblem>> {
    let (socket, session) = stream.get_ref();
    let peer_addr = socket.peer_addr()?;
    let (c2s, s2c) = extract_session_keys(session);

    let request = make_ntske_request();
    debug!("Sending NTS-KE request to {}", peer_addr);
    trace!("NTS-KE request body: {:?}", request);

    write_records_async(stream, &request, false).await?;
    let response = read_records_async(stream).await?;

    debug!("Got NTS-KE response from {}", peer_addr);
    trace!("Got NTS-KE response body: {:?}", response);
    Ok(interpret_ntske_response(response).map(|cookies| NtskeOutput { cookies, c2s, s2c }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::iter;

    #[derive(Debug, Clone)]
    struct NtskeRecords(Vec<NtskeRecord>);

    impl Arbitrary for NtskeRecords {
        fn arbitrary<G: Gen>(g: &mut G) -> NtskeRecords {
            let num_records = g.gen_range(0, g.size());
            NtskeRecords(Vec::from_iter(
                iter::repeat_with(|| NtskeRecord::arbitrary(g))
                    .filter(|record| *record != NtskeRecord::EndOfMessage)
                    .take(num_records)
                    .chain(iter::once(NtskeRecord::EndOfMessage)),
            ))
        }
    }

    fn qc_tests() -> u64 {
        let default = 100;
        match env::var("QUICKCHECK_TESTS") {
            Ok(val) => val.parse().unwrap_or(default),
            Err(_) => default,
        }
    }

    fn qc_gen_size() -> usize {
        let default = 100;
        match env::var("QUICKCHECK_GENERATOR_SIZE") {
            Ok(val) => val.parse().unwrap_or(default),
            Err(_) => default,
        }
    }

    #[tokio::test]
    async fn records_round_trip() {
        let mut g = quickcheck::StdGen::new(rand::rngs::StdRng::from_entropy(), qc_gen_size());
        for _ in 0..qc_tests() {
            let mut buf = Vec::new();
            let records_written = NtskeRecords::arbitrary(&mut g).0;
            let as_response = bool::arbitrary(&mut g);
            write_records_async(&mut buf, &records_written, as_response)
                .await
                .unwrap();
            let mut buf_ptr = buf.as_slice();
            let records_read = read_records_async(&mut buf_ptr).await.unwrap();
            assert!(buf_ptr.is_empty()); //Assert the whole buffer was consumed
            assert_eq!(records_written, records_read);
        }
    }

    #[test]
    fn self_serve() {
        let request = make_ntske_request();
        let master_key_id = 0;
        let master_key = Aes128SivKey::default();
        let c2s = Aes128SivKey::default();
        let s2c = Aes128SivKey::default();
        let response = respond_to_ntske_request(&request, &master_key, master_key_id, &c2s, &s2c);
        let result = interpret_ntske_response(response).unwrap();
        assert!(result.len() == 8)
    }
}
