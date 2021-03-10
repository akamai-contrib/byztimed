//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//! Send time requests and process responses

use crate::aead::*;
use crate::config::PeerConfig;
use crate::core;
use crate::ntske;
use crate::peer_name::PeerName;
use crate::store::{SecretStore, StoreError};
use crate::wire;
use bytes::Buf;
use byztime::{Era, Timestamp};
use log::{debug, log, trace};
use prost::Message;
use rand::RngCore;
use std::convert::TryFrom;
use std::fmt;
use std::net::SocketAddr;
use std::sync::RwLock;
use tokio::io;
use tokio::net;

///Enumeration of errors that can occur when sending a request
#[derive(Debug)]
pub enum RequestError {
    ResolveError(trust_dns_resolver::error::ResolveError),
    CookieLookupError(StoreError),
    C2SLookupError(StoreError),
    TcpError(io::Error),
    TlsHandshakeError(io::Error),
    TlsSessionError(io::Error),
    NtskeProblem(ntske::NtskeProblem),
    NtskeNoCookies,
    CredentialSaveError(StoreError),
    CoreTickError(io::Error),
    CoreDepartureError(io::Error),
    UdpSocketError(io::Error),
}

impl RequestError {
    ///Level that this error should be logged at
    pub fn level(&self) -> log::Level {
        use log::Level::*;
        use RequestError::*;
        match self {
            ResolveError(_) => Warn,
            CookieLookupError(_) => Error,
            C2SLookupError(_) => Error,
            TcpError(_) => Warn,
            TlsHandshakeError(_) => Warn,
            TlsSessionError(_) => Warn,
            NtskeProblem(_) => Warn,
            NtskeNoCookies => Warn,
            CredentialSaveError(_) => Error,
            CoreTickError(_) => Error,
            CoreDepartureError(_) => Error,
            UdpSocketError(_) => Error,
        }
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use RequestError::*;
        match self {
            ResolveError(e) => write!(f, "Resolving DNS: {}", e),
            CookieLookupError(e) => write!(f, "Looking up cookie from store: {}", e),
            C2SLookupError(e) => write!(f, "Looking up C2S key from store: {}", e),
            TcpError(e) => write!(f, "Establishing TCP connection for NTS-KE: {}", e),
            TlsHandshakeError(e) => write!(f, "During TLS handshake: {}", e),
            TlsSessionError(e) => write!(f, "In TLS session: {}", e),
            NtskeProblem(e) => write!(f, "In NTS-KE response: {:?}", e),
            NtskeNoCookies => write!(f, "NTS-KE succeeded but no cookies were returned"),
            CredentialSaveError(e) => write!(f, "Saving credentials to store: {}", e),
            CoreTickError(e) => write!(f, "Handling tick in core: {}", e),
            CoreDepartureError(e) => write!(f, "Updating origin timestamp: {}", e),
            UdpSocketError(e) => write!(f, "Sending on UDP socket: {}", e),
        }
    }
}

impl std::error::Error for RequestError {}

pub fn serialize_time_request(
    out: &mut Vec<u8>,
    unique_id: &core::UniqueId,
    c2s: &Aes128SivKey,
    cookie: Vec<u8>,
    cookies_requested: usize,
) {
    let plaintext = wire::Request {
        num_cookies: cookies_requested as u32,
    };

    trace!(
        "Encoding plaintext for time request {:x?}: {:?}",
        unique_id,
        plaintext
    );

    let mut plaintext_serialized = Vec::with_capacity(plaintext.encoded_len());
    plaintext
        .encode(&mut plaintext_serialized)
        .expect("Error encoding plaintext for time request");

    let cookie_len = cookie.len();

    let mut nonce = Aes128SivNonce::default();
    rand::thread_rng().fill_bytes(nonce.as_mut_slice());

    let ad = wire::RequestAd {
        unique_id: unique_id.to_vec(),
        cookie,
    };

    trace!(
        "Encoding associated data for time request {:x?}: {:?}",
        unique_id,
        ad
    );

    let mut ad_serialized = Vec::with_capacity(ad.encoded_len());
    ad.encode(&mut ad_serialized)
        .expect("Error encoding associated data for time request");

    let aead_c2s = Aes128SivAead::new(c2s);

    let ciphertext = aead_c2s
        .encrypt(
            &nonce,
            Payload {
                aad: &ad_serialized,
                msg: &plaintext_serialized,
            },
        )
        .expect("Error encrypting time request");

    let padding = vec![0; cookie_len * cookies_requested.saturating_sub(1) + wire::EXTRA_PADDING];

    let packet = wire::Packet {
        msg: Some(wire::packet::Msg::Request(wire::RequestEnvelope {
            nonce: nonce.to_vec(),
            ad: ad_serialized,
            ciphertext,
            padding,
        })),
    };

    trace!(
        "Encoding packet for time request {:x?}: {:?}",
        unique_id,
        packet
    );

    out.reserve(packet.encoded_len());
    packet
        .encode(out)
        .expect("Error encoding packet for time request");
}

///Send a time request
///
///Resolve `peer_config.host` using `resolver`. Take keys and cookies
/// from `secret_store`. If they aren't there, run NTS-KE to obtain
/// them.  Send a time request over `socket_mutex` and record in
/// `core_state` that it's in flight.
pub async fn send_time_request(
    resolver: &trust_dns_resolver::TokioAsyncResolver,
    socket: &tokio::net::UdpSocket,
    peer_name: &PeerName,
    peer_config: &PeerConfig,
    core_state: &RwLock<core::CoreState>,
    secret_store: &SecretStore,
) -> Result<(), RequestError> {
    let ip_addr = resolver
        .lookup_ip(peer_config.host.as_str())
        .await
        .map_err(RequestError::ResolveError)?
        .into_iter()
        .next()
        .expect("Got empty iterator from DNS lookup");

    debug!(
        "Resolved DNS for peer '{}': {} -> {}",
        peer_name, peer_config.host, ip_addr
    );

    let peer_addr = SocketAddr::new(ip_addr, peer_config.port);

    //These two secret_store calls each use separate transactions, so
    // it's possible to get a cookie that doesn't correspond to to the
    // c2s key if the results of an NTS-KE exchange get committed in
    // between the two calls. This can be elicited in testing by
    // setting an extremely short polling interval. Preventing this
    // would be easy — just add a method to SecretStore that fetches
    // both the C2S key and the cookie in a single transaction — but
    // it wouldn't actually improve anything because the new S2C key
    // will still get committed right afterward and we won't be able
    // to decrypt the server's response. The problem is harmless in
    // any case because we'll just recover on the next tick. Worst
    // that happens is that NTS-KE gets run twice rather than just
    // once.
    let (c2s, cookie, cookies_left) = match (
        secret_store
            .get_c2s_key(peer_name)
            .map_err(RequestError::C2SLookupError)?,
        secret_store
            .take_cookie(peer_name)
            .map_err(RequestError::CookieLookupError)?,
    ) {
        (Some(c2s), (Some(cookie), cookies_left)) => (c2s, cookie, cookies_left),
        _ => {
            let tcp_stream = net::TcpStream::connect(&peer_addr)
                .await
                .map_err(RequestError::TcpError)?;
            debug!(
                "TCP connection established for NTS-KE with peer '{}'",
                peer_name
            );
            let mut tls_stream = peer_config
                .tls_connector
                .connect(peer_config.cert_name.as_ref(), tcp_stream)
                .await
                .map_err(RequestError::TlsHandshakeError)?;
            debug!("TLS handshake completed with peer '{}'", peer_name);
            let mut ntske_output = ntske::request_ntske(&mut tls_stream)
                .await
                .map_err(RequestError::TlsSessionError)?
                .map_err(RequestError::NtskeProblem)?;
            debug!("Successful NTS-KE with peer '{}'", peer_name);
            let my_cookie = ntske_output
                .cookies
                .pop()
                .ok_or(RequestError::NtskeNoCookies)?;
            let cookies_left = ntske_output.cookies.len();
            secret_store
                .set_credentials(
                    peer_name,
                    &ntske_output.c2s,
                    &ntske_output.s2c,
                    ntske_output.cookies.as_slice(),
                )
                .map_err(RequestError::CredentialSaveError)?;
            debug!(
                "Stored session keys and {} cookies for peer '{}'",
                cookies_left, peer_name
            );
            (ntske_output.c2s, my_cookie, cookies_left)
        }
    };

    let query = core_state
        .write()
        .unwrap()
        .on_tick(peer_name, &mut rand::thread_rng())
        .map_err(RequestError::CoreTickError)?;
    let cookies_requested = if cookies_left > 7 {
        1
    } else {
        8 - cookies_left
    };

    let mut send_buf = Vec::new();
    serialize_time_request(
        &mut send_buf,
        &query.unique_id,
        &c2s,
        cookie,
        cookies_requested,
    );

    core_state
        .write()
        .unwrap()
        .on_departure(peer_name)
        .map_err(RequestError::CoreDepartureError)?;

    debug!("Sending time request to peer '{}'", peer_name);

    socket
        .send_to(send_buf.as_slice(), &peer_addr)
        .await
        .map_err(RequestError::UdpSocketError)?;
    Ok(())
}

///Enumeration of errors that can occur when processing a time response
#[derive(Debug)]
pub enum ResponseError {
    DestTimeError(io::Error),
    PacketDecodingError(prost::DecodeError),
    NotAResponse,
    AdDecodingError(prost::DecodeError),
    WrongNonceLength,
    WrongUniqueIdLength,
    UnrecognizedErrorResponse,
    NonMatchingUniqueId,
    S2CLookupError(PeerName, StoreError),
    S2CNotFound(PeerName),
    DecryptionFailure(PeerName),
    PlaintextDecodingError(PeerName, prost::DecodeError),
    WrongEraLength(PeerName),
    NoLocalClock(PeerName),
    NoGlobalOffset(PeerName),
    CoreError(PeerName, io::Error),
    StoreCookiesError(PeerName, StoreError),
    StoreClearError(PeerName, StoreError),
}

impl ResponseError {
    fn level(&self) -> log::Level {
        use log::Level::*;
        use ResponseError::*;
        match self {
            DestTimeError(_) => Error,
            PacketDecodingError(_) => Debug,
            NotAResponse => Debug,
            AdDecodingError(_) => Debug,
            WrongNonceLength => Debug,
            WrongUniqueIdLength => Debug,
            UnrecognizedErrorResponse => Debug,
            NonMatchingUniqueId => Debug,
            S2CLookupError(_, _) => Error,
            S2CNotFound(_) => Warn,
            DecryptionFailure(_) => Warn,
            PlaintextDecodingError(_, _) => Warn,
            WrongEraLength(_) => Warn,
            NoLocalClock(_) => Warn,
            NoGlobalOffset(_) => Warn,
            CoreError(_, _) => Error,
            StoreCookiesError(_, _) => Error,
            StoreClearError(_, _) => Error,
        }
    }
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ResponseError::*;
        match self {
            DestTimeError(e) => write!(f, "Getting destination timestamp: {}", e),
            PacketDecodingError(e) => write!(f, "Decoding packet: {}", e),
            NotAResponse => write!(f, "Not a response packet"),
            AdDecodingError(e) => write!(f, "Decoding associated data: {}", e),
            WrongNonceLength => write!(f, "Wrong nonce length"),
            WrongUniqueIdLength => write!(f, "Wrong unique-ID length"),
            UnrecognizedErrorResponse => write!(f, "Unrecognized error response"),
            NonMatchingUniqueId => {
                write!(f, "Unique-ID does not correspond to any in-flight request")
            }
            S2CLookupError(peer, e) => write!(f, "Looking up S2C for peer '{}': {}", peer, e),
            S2CNotFound(peer) => write!(f, "S2C key not found for peer '{}'", peer),
            DecryptionFailure(peer) => write!(f, "Failed to decrypt response from peer '{}'", peer),
            PlaintextDecodingError(peer, e) => {
                write!(f, "Decoding plaintext send by peer '{}': {}", peer, e)
            }
            WrongEraLength(peer) => write!(
                f,
                "Response from peer '{}' has an era of the wrong length",
                peer
            ),
            NoLocalClock(peer) => write!(
                f,
                "Response from peer '{}' is missing its local-clock field",
                peer
            ),
            NoGlobalOffset(peer) => write!(
                f,
                "Response from peer '{}' is missing its global-offset field",
                peer
            ),
            CoreError(peer, e) => write!(
                f,
                "Updating core state for response from peer '{}': {}",
                peer, e
            ),
            StoreCookiesError(peer, e) => write!(
                f,
                "Writing new cookies from peer '{}' to secret store: {}",
                peer, e
            ),
            StoreClearError(peer, e) => write!(
                f,
                "Clearing secret store in response to crypto-NAK from peer '{}': {}",
                peer, e
            ),
        }
    }
}

impl std::error::Error for ResponseError {}

///Data extracted from a [wire::ResponseEnvelope](../wire/struct.ResponseEnvelope.html)
pub struct ResponseEnvelopeData {
    unique_id: core::UniqueId,
    nonce: Aes128SivNonce,
    ad: Vec<u8>,
    ciphertext: Vec<u8>,
}

///Data extracted from a crypto-NAK response
pub struct CryptoNakData {
    unique_id: core::UniqueId,
}

///Deserialize a time response as far as the envelope, but don't try to decrypt it
pub fn deserialize_response_envelope<Response: Buf>(
    response: Response,
) -> Result<Result<ResponseEnvelopeData, CryptoNakData>, ResponseError> {
    let packet = wire::Packet::decode(response).map_err(ResponseError::PacketDecodingError)?;
    trace!("Deserialized time response packet: {:?}", packet);

    match packet.msg {
        Some(wire::packet::Msg::Response(envelope)) => {
            let ad = wire::ResponseAd::decode(envelope.ad.as_ref())
                .map_err(ResponseError::AdDecodingError)?;
            let nonce = Aes128SivNonce::try_clone_from_slice(envelope.nonce.as_slice())
                .map_err(|_| ResponseError::WrongNonceLength)?;
            let unique_id = core::UniqueId::try_from(ad.unique_id.as_slice())
                .map_err(|_| ResponseError::WrongUniqueIdLength)?;
            Ok(Ok(ResponseEnvelopeData {
                unique_id,
                nonce,
                ad: envelope.ad,
                ciphertext: envelope.ciphertext,
            }))
        }
        Some(wire::packet::Msg::Error(error)) => {
            let unique_id = core::UniqueId::try_from(error.unique_id.as_slice())
                .map_err(|_| ResponseError::WrongUniqueIdLength)?;
            match error.error {
                Some(wire::error::Error::CryptoNak(_)) => Ok(Err(CryptoNakData { unique_id })),
                _ => Err(ResponseError::UnrecognizedErrorResponse),
            }
        }
        _ => Err(ResponseError::NotAResponse),
    }
}

///Deserialize the plaintext of a time response, returning cookies and
/// a [`core::Response`](../core/struct.Response.html).
pub fn deserialize_response_plaintext<Plaintext: Buf>(
    peer_name: &PeerName,
    unique_id: &core::UniqueId,
    plaintext: Plaintext,
) -> Result<(Vec<Vec<u8>>, core::Response), ResponseError> {
    let response = wire::Response::decode(plaintext)
        .map_err(|e| ResponseError::PlaintextDecodingError(peer_name.clone(), e))?;
    trace!("Deserialized time response plaintext: {:?}", response);
    let era = Era(<[u8; 16]>::try_from(response.era.as_slice())
        .map_err(|_| ResponseError::WrongEraLength(peer_name.clone()))?);

    let global_offset = response
        .offset
        .ok_or_else(|| ResponseError::NoGlobalOffset(peer_name.clone()))?;
    let local_clock = response
        .local_clock
        .ok_or_else(|| ResponseError::NoLocalClock(peer_name.clone()))?;
    Ok((
        response.cookies,
        core::Response {
            era,
            unique_id: *unique_id,
            global_offset: Timestamp::new(
                global_offset.seconds as i64,
                global_offset.nanoseconds as i64,
            ),
            local_clock: Timestamp::new(local_clock.seconds as i64, local_clock.nanoseconds as i64),
        },
    ))
}

///Process a time response
///
///Deserialize and decrypt the `response` using `secret_store` to look up keys.
/// Pass the response to `core_state`. Add any returned cookies to the store.
pub fn handle_time_response<Response: Buf>(
    response: Response,
    core_state: &RwLock<core::CoreState>,
    secret_store: &SecretStore,
) -> Result<(), ResponseError> {
    let dest_time = Timestamp::local_time().map_err(ResponseError::DestTimeError)?;

    match deserialize_response_envelope(response)? {
        Ok(envelope) => {
            let peer_name = core_state
                .read()
                .unwrap()
                .lookup_peer(&envelope.unique_id)
                .ok_or(ResponseError::NonMatchingUniqueId)?;
            //It's possible for S2CNotFound to happen when request B
            // crosses request A on the wire, and response B is a
            // crypto-NAK which causes us to clear our
            // credentials. This can readily be elicited in testing
            // setting an extremely short polling interval, but should
            // never normally happen in production, barring
            // adversarial behavior by the network or the peer.  If it
            // does, it's harmless; we'll log it at WARN level and
            // recover on the next tick.
            let s2c = secret_store
                .get_s2c_key(&peer_name)
                .map_err(|e| ResponseError::S2CLookupError(peer_name.clone(), e))?
                .ok_or_else(|| ResponseError::S2CNotFound(peer_name.clone()))?;
            let aead_s2c = Aes128SivAead::new(&s2c);
            let plaintext = aead_s2c
                .decrypt(
                    &envelope.nonce,
                    Payload {
                        aad: &envelope.ad,
                        msg: &envelope.ciphertext,
                    },
                )
                .map_err(|_| ResponseError::DecryptionFailure(peer_name.clone()))?;
            let (cookies, response) = deserialize_response_plaintext(
                &peer_name,
                &envelope.unique_id,
                plaintext.as_ref(),
            )?;
            core_state
                .write()
                .unwrap()
                .on_response(&response, dest_time)
                .map_err(|e| ResponseError::CoreError(peer_name.clone(), e))?;

            secret_store
                .give_cookies(&peer_name, cookies)
                .map_err(|e| ResponseError::StoreCookiesError(peer_name.clone(), e))?;
            debug!(
                "Successfully handled time response from peer '{}'",
                peer_name
            );
            Ok(())
        }
        Err(crypto_nak) => {
            let peer_name = core_state
                .read()
                .unwrap()
                .lookup_peer(&crypto_nak.unique_id)
                .ok_or(ResponseError::NonMatchingUniqueId)?;
            debug!("Received crypto-NAK from peer '{}'", peer_name);
            secret_store
                .clear_peer(&peer_name)
                .map_err(|e| ResponseError::StoreClearError(peer_name.clone(), e))?;
            Ok(())
        }
    }
}

///Listen for time response and process them
///
///Listen forever on `socket`. Process any responses that come in. If any
/// errors occur, log them and continue.
pub async fn time_response_listener(
    socket: &tokio::net::UdpSocket,
    core_state: &RwLock<core::CoreState>,
    secret_store: &SecretStore,
) -> io::Result<()> {
    let mut recv_buf = [0; 65535];
    loop {
        let (recv_size, peer_addr) = socket.recv_from(&mut recv_buf).await?;
        if let Err(e) = handle_time_response(&recv_buf[0..recv_size], core_state, secret_store) {
            log!(
                e.level(),
                "Handling time response from {}: {}",
                peer_addr,
                e
            );
        }
    }
}
