//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

use crate::aead::*;
use crate::config;
use crate::cookie;
use crate::core;
use crate::peer_name::PeerName;
use crate::store;
use crate::time_client;
use crate::time_server;

use std::collections;
use std::net;
use std::path;
use std::sync::{Arc, RwLock};
use tokio_rustls::rustls;
use tokio_rustls::webpki::DNSNameRef;

#[test]
fn round_trip() {
    /* Set up a fake server */
    let server_timedata_path = tempfile::NamedTempFile::new().unwrap();
    let server_store_path = tempfile::tempdir().unwrap();
    let server_config = config::Config {
        timedata: path::PathBuf::from(server_timedata_path.path()),
        secret_store: path::PathBuf::from(server_store_path.path()),
        logging: vec![],
        ro_mode: false,
        bind_host: net::IpAddr::V6(net::Ipv6Addr::UNSPECIFIED),
        bind_port: 0,
        poll_interval: 8.0,
        drift_ppb: 250_000,
        tls_acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(rustls::ServerConfig::new(
            rustls::NoClientAuth::new(),
        ))),
        log_format: None,
        peers: collections::HashMap::new(),
    };
    let server_core_state_lock = RwLock::new(core::CoreState::initialize(&server_config).unwrap());
    let server_secret_store = store::SecretStore::new(&server_config.secret_store).unwrap();

    /* ...and a fake client */
    let client_timedata_path = tempfile::NamedTempFile::new().unwrap();
    let client_store_path = tempfile::tempdir().unwrap();
    let peer_name = PeerName::new("server".into());
    let mut client_peers = collections::HashMap::new();
    client_peers.insert(
        peer_name.clone(),
        Arc::new(config::PeerConfig {
            host: "".into(),
            port: 0,
            dist: 0,
            cert_name: DNSNameRef::try_from_ascii_str("bogus.invalid")
                .unwrap()
                .to_owned(),
            tls_connector: tokio_rustls::TlsConnector::from(Arc::new(rustls::ClientConfig::new())),
        }),
    );

    let client_config = config::Config {
        timedata: path::PathBuf::from(client_timedata_path.path()),
        secret_store: path::PathBuf::from(client_store_path.path()),
        logging: vec![],
        ro_mode: true,
        bind_host: net::IpAddr::V6(net::Ipv6Addr::UNSPECIFIED),
        bind_port: 0,
        poll_interval: 8.0,
        drift_ppb: 250_000,
        tls_acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(rustls::ServerConfig::new(
            rustls::NoClientAuth::new(),
        ))),
        log_format: None,
        peers: client_peers,
    };
    let client_core_state_lock = RwLock::new(core::CoreState::initialize(&client_config).unwrap());
    let client_secret_store = store::SecretStore::new(&client_config.secret_store).unwrap();

    /* Create some credentials and populate the client's secret store */
    let (master_key_id, master_key) = server_secret_store.get_cached_current_master_key();
    let mut rng = rand::thread_rng();
    let c2s = keygen(&mut rng);
    let s2c = keygen(&mut rng);
    let cookie = cookie::seal_cookie(
        &cookie::CookieData { c2s, s2c },
        &master_key,
        master_key_id,
        &mut rng,
    );
    client_secret_store
        .set_credentials(&peer_name, &c2s, &s2c, &[cookie.clone()])
        .unwrap();

    /* Make a time request */
    let mut request_buf = Vec::new();
    let query = client_core_state_lock
        .write()
        .unwrap()
        .on_tick(&peer_name, &mut rng)
        .unwrap();
    time_client::serialize_time_request(&mut request_buf, &query.unique_id, &c2s, cookie, 1);

    /* Serve a response */
    let mut response_buf = Vec::with_capacity(65535);
    time_server::respond_to_time_request(
        request_buf.as_ref(),
        &mut response_buf,
        &server_core_state_lock,
        &server_secret_store,
    )
    .unwrap()
    .unwrap();

    /* Interpret the response */
    time_client::handle_time_response(
        response_buf.as_ref(),
        &client_core_state_lock,
        &client_secret_store,
    )
    .unwrap();
}
