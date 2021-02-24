//Copyright 2020, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate bencher;
extern crate rand;
extern crate tempfile;

use bencher::Bencher;
use std::path;
use tokio_rustls::rustls;

fn bench_respond_to_time_request(bench: &mut Bencher) {
    let timedata_path = tempfile::NamedTempFile::new().unwrap();
    let store_path = tempfile::tempdir().unwrap();
    let config = byztimed::config::Config {
        timedata: path::PathBuf::from(timedata_path.path()),
        secret_store: path::PathBuf::from(store_path.path()),
        logging: vec![],
        log_format: None,
        ro_mode: false,
        bind_host: std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        bind_port: 0,
        poll_interval: 8.0,
        drift_ppb: 250_000,
        tls_acceptor: tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
            rustls::ServerConfig::new(rustls::NoClientAuth::new()),
        )),
        peers: std::collections::HashMap::new(),
    };

    let core_state = byztimed::core::CoreState::initialize(&config).unwrap();
    let secret_store = byztimed::store::SecretStore::new(&config.secret_store).unwrap();

    let mut request_buf = Vec::new();
    let mut response_buf = Vec::with_capacity(65535);
    let mut rng = rand::thread_rng();
    let unique_id = byztimed::core::UniqueId::default();
    let c2s = byztimed::aead::keygen(&mut rng);
    let s2c = byztimed::aead::keygen(&mut rng);
    let (master_key_id, master_key) = secret_store.get_cached_current_master_key();
    let cookie = byztimed::cookie::seal_cookie(
        &byztimed::cookie::CookieData { c2s, s2c },
        &master_key,
        master_key_id,
        &mut rng,
    );
    byztimed::time_client::serialize_time_request(&mut request_buf, &unique_id, &c2s, cookie, 1);

    let core_state_mutex = std::sync::RwLock::new(core_state);
    bench.iter(|| {
        byztimed::time_server::respond_to_time_request(
            request_buf.as_ref(),
            &mut response_buf,
            &core_state_mutex,
            &secret_store,
        )
    })
}

benchmark_group!(time_server_benches, bench_respond_to_time_request);
benchmark_main!(time_server_benches);
