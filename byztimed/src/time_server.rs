//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//! Process time requests and send responses

use crate::aead::*;
use crate::cookie;
use crate::core;
use crate::store::SecretStore;
use crate::wire;
use byztime::{Era, Timestamp};
use log::{debug, error, trace};
use prost::Message;
use rand::RngCore;
use std::cmp;
use std::convert::TryFrom;
use std::fmt;
use std::sync::RwLock;
use tokio::io;
use tokio::net;

///Information extracted from a deserialized and decrypted time request
#[derive(Debug, Clone)]
pub struct RequestData {
    ///The unique-id sent with the request
    pub unique_id: core::UniqueId,
    ///The number of cookies requested
    pub num_cookies: usize,
    ///Decypted contents of the cookie sent with the request
    pub cookie_data: cookie::CookieData,
}

///Information necessary to form a response to a time request
#[derive(Debug, Clone)]
pub struct ResponseData {
    ///The unique-id sent with the request
    pub unique_id: core::UniqueId,
    ///The number of cookies that were requsted
    pub num_cookies: usize,
    ///Decypted contents of the cookie sent with the request
    pub cookie_data: cookie::CookieData,
    ///Our clock era
    pub era: Era,
    ///Value of our local clock
    pub local_clock: Timestamp,
    ///Our current estimate of (global clock - local clock)
    pub global_offset: Timestamp,
    ///Master key for encrypting new cookies
    pub master_key: Aes128SivKey,
    ///Master key ID
    pub master_key_id: u32,
}

///Enumeration of anything that can be wrong with a request
#[derive(Debug, Clone)]
pub enum RequestError {
    PacketDecodingError(prost::DecodeError),
    NotARequest,
    AdDecodingError(prost::DecodeError),
    WrongUniqueIdLength,
    NonDecryptableCookie(core::UniqueId),
    WrongNonceLength,
    NonDecryptableCiphertext(core::UniqueId),
    PlaintextDecodingError(prost::DecodeError),
    NotEnoughPadding,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use RequestError::*;

        match self {
            PacketDecodingError(e) => write!(f, "Packet decoding error: {}", e),
            NotARequest => write!(f, "Not a request"),
            AdDecodingError(e) => write!(f, "Associated data decoding error: {}", e),
            WrongUniqueIdLength => write!(f, "Wrong unique-ID length"),
            NonDecryptableCookie(_) => write!(f, "Non-decryptable cookie"),
            WrongNonceLength => write!(f, "Wrong nonce length"),
            NonDecryptableCiphertext(_) => write!(f, "Non-decryptable ciphertext"),
            PlaintextDecodingError(e) => write!(f, "Plaintext decoding error: {}", e),
            NotEnoughPadding => write!(f, "Not enough padding"),
        }
    }
}

impl std::error::Error for RequestError {}

///Deserialize a time request
///
/// Fully deserialize and decrypt `request`, using `get_master_key` to
/// look up master keys by ID
pub fn deserialize_request<
    Request: bytes::Buf,
    GetMasterKey: FnOnce(u32) -> Option<Aes128SivKey>,
>(
    request: Request,
    get_master_key: GetMasterKey,
) -> Result<RequestData, RequestError> {
    let packet = wire::Packet::decode(request).map_err(RequestError::PacketDecodingError)?;
    trace!("Deserialized time request packet: {:?}", packet);

    let envelope = match packet.msg {
        Some(wire::packet::Msg::Request(envelope)) => Ok(envelope),
        _ => Err(RequestError::NotARequest),
    }?;

    let padding_len = envelope.padding.len();

    let ad =
        wire::RequestAd::decode(envelope.ad.as_ref()).map_err(RequestError::AdDecodingError)?;

    trace!("Deserialized time request associated data: {:?}", ad);

    let unique_id = core::UniqueId::try_from(ad.unique_id.as_slice())
        .map_err(|_| RequestError::WrongUniqueIdLength)?;

    let cookie_len = ad.cookie.len();

    let cookie_data = cookie::open_cookie(&ad.cookie, get_master_key)
        .ok_or(RequestError::NonDecryptableCookie(unique_id))?;

    let aead_c2s = Aes128SivAead::new(&cookie_data.c2s);

    let nonce = Aes128SivNonce::try_from_slice(&envelope.nonce)
        .map_err(|_| RequestError::WrongNonceLength)?;

    let plaintext_serialized = aead_c2s
        .decrypt(
            nonce,
            Payload {
                aad: &envelope.ad,
                msg: &envelope.ciphertext,
            },
        )
        .map_err(|_| RequestError::NonDecryptableCiphertext(unique_id))?;

    let plaintext = wire::Request::decode(plaintext_serialized.as_ref())
        .map_err(RequestError::PlaintextDecodingError)?;

    trace!("Deserialized time request plaintext: {:?}", plaintext);

    let num_cookies = cmp::min(plaintext.num_cookies, 8) as usize;

    if padding_len < cookie_len.saturating_mul(num_cookies.saturating_sub(1)) + wire::EXTRA_PADDING
    {
        return Err(RequestError::NotEnoughPadding);
    }

    Ok(RequestData {
        unique_id,
        num_cookies,
        cookie_data,
    })
}

///Construct a crypto-NAK error response
pub fn serialize_crypto_nak(out: &mut Vec<u8>, unique_id: &core::UniqueId) {
    let packet = wire::Packet {
        msg: Some(wire::packet::Msg::Error(wire::Error {
            unique_id: unique_id.to_vec(),
            error: Some(wire::error::Error::CryptoNak(wire::CryptoNak {})),
        })),
    };
    out.reserve(packet.encoded_len());
    packet.encode(out).expect("Error encoding crypto-NAK");
}

///Construct a time response
pub fn serialize_response(out: &mut Vec<u8>, response_data: &ResponseData) {
    let mut cookies = Vec::with_capacity(response_data.num_cookies);
    for _ in 0..response_data.num_cookies {
        let cookie = cookie::seal_cookie(
            &response_data.cookie_data,
            &response_data.master_key,
            response_data.master_key_id,
            &mut rand::thread_rng(),
        );
        cookies.push(cookie);
    }

    let plaintext = wire::Response {
        era: response_data.era.0.to_vec(),
        local_clock: Some(wire::Timestamp {
            seconds: response_data.local_clock.seconds(),
            nanoseconds: response_data.local_clock.nanoseconds() as u32,
        }),
        offset: Some(wire::Timestamp {
            seconds: response_data.global_offset.seconds(),
            nanoseconds: response_data.global_offset.nanoseconds() as u32,
        }),
        cookies,
    };

    trace!("Serializing time response plaintext: {:?}", plaintext);

    let mut plaintext_serialized = Vec::with_capacity(plaintext.encoded_len());
    plaintext
        .encode(&mut plaintext_serialized)
        .expect("Error encoding plaintext in time response");
    let ad = wire::ResponseAd {
        unique_id: response_data.unique_id.to_vec(),
    };

    let mut nonce = Aes128SivNonce::default();
    rand::thread_rng().fill_bytes(nonce.as_mut_slice());

    trace!("Serializing time response associated data: {:?}", ad);

    let mut ad_serialized = Vec::with_capacity(ad.encoded_len());
    ad.encode(&mut ad_serialized)
        .expect("Error encoding associated data in time response");

    let aead_s2c = Aes128SivAead::new(&response_data.cookie_data.s2c);
    let ciphertext = aead_s2c
        .encrypt(
            &nonce,
            Payload {
                aad: &ad_serialized,
                msg: &plaintext_serialized,
            },
        )
        .expect("Failed to encrypt time response");

    let packet = wire::Packet {
        msg: Some(wire::packet::Msg::Response(wire::ResponseEnvelope {
            ad: ad_serialized,
            nonce: nonce.to_vec(),
            ciphertext,
        })),
    };

    trace!("Serializing time response packet: {:?}", packet);

    out.reserve(packet.encoded_len());
    packet
        .encode(out)
        .expect("Error encoding packet in time response");
}

///Costruct a response to a time request
///
///Parses the request in `recv_buf` and places an appropriate response in `send_buf`.
/// Returns as follows:
/// * `Ok(Ok(()))`: We're replying normally
/// * `(Ok(Err(e, true)))`: There was a problem with the request we should send back an error response
/// * `(Ok(Err(e, false)))`: The was a problem with the request and it's too malformed to reply to
/// * `Err(e)`: We hit an internal error querying core_state
pub fn respond_to_time_request<Request: bytes::Buf>(
    recv_buf: Request,
    send_buf: &mut Vec<u8>,
    core_state: &RwLock<core::CoreState>,
    secret_store: &SecretStore,
) -> io::Result<Result<(), (RequestError, bool)>> {
    let get_master_key = |key_id| secret_store.get_cached_master_key(key_id);

    match deserialize_request(recv_buf, get_master_key) {
        Ok(request_data) => {
            let (master_key_id, master_key) = secret_store.get_cached_current_master_key();
            let core_response = core_state
                .read()
                .unwrap()
                .on_query(&core::Query {
                    unique_id: request_data.unique_id,
                })
                .map_err(io::Error::from)?;
            let response_data = ResponseData {
                unique_id: core_response.unique_id,
                num_cookies: request_data.num_cookies,
                cookie_data: request_data.cookie_data,
                era: core_response.era,
                local_clock: core_response.local_clock,
                global_offset: core_response.global_offset,
                master_key,
                master_key_id,
            };
            send_buf.clear();
            serialize_response(send_buf, &response_data);
            Ok(Ok(()))
        }
        Err(request_problem) => {
            let maybe_unique_id = match request_problem {
                RequestError::NonDecryptableCookie(unique_id) => Some(unique_id),
                RequestError::NonDecryptableCiphertext(unique_id) => Some(unique_id),
                _ => None,
            };

            if let Some(ref unique_id) = maybe_unique_id {
                send_buf.clear();
                serialize_crypto_nak(send_buf, unique_id);
                Ok(Err((request_problem, true)))
            } else {
                Ok(Err((request_problem, false)))
            }
        }
    }
}

///Serve time
///
/// Listen forever on `socket` and reply to any time requests received.
pub async fn serve_time(
    socket: &mut net::UdpSocket,
    core_state: &RwLock<core::CoreState>,
    secret_store: &SecretStore,
) -> io::Result<()> {
    let mut recv_buf = [0; 65535];
    let mut send_buf = Vec::with_capacity(65535);

    loop {
        let (recv_size, peer_addr) = socket.recv_from(&mut recv_buf).await?;
        debug!(
            "Time server got packet of length {} from {}",
            recv_size, peer_addr
        );

        match respond_to_time_request(
            &recv_buf[0..recv_size],
            &mut send_buf,
            core_state,
            secret_store,
        ) {
            Ok(Ok(())) => {
                debug!(
                    "Sending time response of length {} to {}",
                    send_buf.len(),
                    peer_addr
                );
                socket.send_to(send_buf.as_slice(), peer_addr).await?;
            }

            Ok(Err((problem, should_reply))) => {
                debug!("Error in time request from {}: {}", peer_addr, problem);
                if should_reply {
                    socket.send_to(send_buf.as_slice(), peer_addr).await?;
                }
            }

            Err(e) => error!(
                "From CoreState::on_query(), responding to time request from {}: {}",
                peer_addr, e
            ),
        }
    }
}
