//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

use byztimed::config::{Config, ConfigError};
use byztimed::core;
use byztimed::logging::{init_logging, reinit_logging, LogHandle};
use byztimed::ntske;
use byztimed::peer_name::PeerName;
use byztimed::store::{SecretStore, StoreError};
use byztimed::time_client;
use byztimed::time_server;
use std::fmt;
use std::fs;
use std::future::Future;
use std::net;
use std::path;
use std::process;
use std::sync::*;
use tokio::io;
use tokio::net::{TcpListener, UdpSocket};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::time;

#[macro_use]
extern crate log;

struct GlobalState {
    cfg: Config,
    core_state: RwLock<core::CoreState>,
    secret_store: SecretStore,
    shutdown_sender: mpsc::UnboundedSender<Result<(), FatalError>>,
}

#[derive(Debug)]
///Enumeration of errors that will make us terminate the program
enum FatalError {
    ArgumentError(clap::Error),
    ConfigReadError(io::Error),
    ConfigDecodeError(std::string::FromUtf8Error),
    ConfigErrors(ConfigError),
    LogInitError(io::Error),
    TimedataError(io::Error),
    StoreError(StoreError),
    ResolverError(trust_dns_resolver::error::ResolveError),
    TcpBindError(io::Error),
    UdpServerBindError(io::Error),
    UdpClientBindError(io::Error),
    ChildTaskError(io::Error),
    ChildTaskJoinError(tokio::task::JoinError),
}

impl fmt::Display for FatalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FatalError::*;
        match self {
            ArgumentError(e) => e.fmt(f),
            ConfigReadError(e) => write!(f, "Reading configuration file: {}", e),
            ConfigDecodeError(e) => write!(f, "UTF-8 decoding configuration file: {}", e),
            ConfigErrors(e) => e.fmt(f),
            LogInitError(e) => write!(f, "Initializing logging: {}", e),
            TimedataError(e) => write!(f, "Opening timedata file: {}", e),
            StoreError(e) => write!(f, "Opening secret store: {}", e),
            ResolverError(e) => write!(f, "Initializing DNS resolver: {}", e),
            TcpBindError(e) => write!(f, "Binding NTS-KE server socket: {}", e),
            UdpServerBindError(e) => write!(f, "Binding server UDP socket: {}", e),
            UdpClientBindError(e) => write!(f, "Binding client UDP socket: {}", e),
            ChildTaskError(e) => write!(f, "IO error in child task: {}", e),
            ChildTaskJoinError(e) => write!(f, "Child task join error: {}", e),
        }
    }
}

impl std::error::Error for FatalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FatalError::*;
        match self {
            ArgumentError(e) => Some(e),
            ConfigReadError(e) => Some(e),
            ConfigDecodeError(e) => Some(e),
            ConfigErrors(e) => Some(e),
            LogInitError(e) => Some(e),
            TimedataError(e) => Some(e),
            StoreError(_) => None, //StoreError doesn't implement std::error::Error
            ResolverError(_) => None,
            TcpBindError(e) => Some(e),
            UdpServerBindError(e) => Some(e),
            UdpClientBindError(e) => Some(e),
            ChildTaskError(e) => Some(e),
            ChildTaskJoinError(e) => Some(e),
        }
    }
}

fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    if let Err(e) = runtime.block_on(async_main()) {
        eprintln!("{}", e);
        process::exit(1)
    }
}

async fn async_main() -> Result<(), FatalError> {
    /* Parse the command line */
    let matches = clap::App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            clap::Arg::with_name("cfg_file")
                .help("Path to configuration file")
                .required(true)
                .index(1),
        )
        .get_matches_safe()
        .map_err(FatalError::ArgumentError)?;

    /* Parse the configuration file */
    let cfg_path = path::Path::new(matches.value_of_os("cfg_file").unwrap());
    let cfg_bytestring = fs::read(cfg_path).map_err(FatalError::ConfigReadError)?;
    let cfg_contents = String::from_utf8(cfg_bytestring).map_err(FatalError::ConfigDecodeError)?;
    let cfg = Config::parse(&cfg_contents).map_err(FatalError::ConfigErrors)?;

    /* Initialize logging */
    let log_handle = init_logging(&cfg.logging, cfg.log_format.as_ref().map(|s| s.as_str()))
        .map_err(FatalError::LogInitError)?;

    /* Open the timedata file and secret store and initialize various bits of
    global state. */

    let (shutdown_sender, mut shutdown_receiver) = mpsc::unbounded_channel();

    let state = Arc::new(GlobalState {
        core_state: RwLock::new(
            core::CoreState::initialize(&cfg).map_err(FatalError::TimedataError)?,
        ),
        secret_store: SecretStore::new(&cfg.secret_store.as_path())
            .map_err(FatalError::StoreError)?,
        shutdown_sender,
        cfg,
    });

    /* Initialize the DNS resolver */
    let resolver = Arc::new(
        trust_dns_resolver::AsyncResolver::tokio_from_system_conf()
            .map_err(FatalError::ResolverError)?,
    );

    /* Spawn signal handlers */
    watch(
        state.clone(),
        shutdown_signal_task(state.clone(), SignalKind::interrupt(), "SIGINT"),
        "SIGINT handler",
    )
    .await;
    watch(
        state.clone(),
        shutdown_signal_task(state.clone(), SignalKind::terminate(), "SIGTERM"),
        "SIGTERM handler",
    )
    .await;
    watch(
        state.clone(),
        logrotate_signal_task(log_handle, state.clone(), SignalKind::hangup(), "SIGHUP"),
        "SIGHUP handler",
    )
    .await;

    /* Spawn a task for periodically updating our real-time offset */
    watch(
        state.clone(),
        update_real_offset_task(state.clone()),
        "real offset updater",
    )
    .await;

    /* Bind server sockets and spawn associated tasks */
    if !state.cfg.ro_mode {
        let server_addr = net::SocketAddr::new(state.cfg.bind_host, state.cfg.bind_port);
        let ntske_server_socket = TcpListener::bind(&server_addr)
            .await
            .map_err(FatalError::TcpBindError)?;
        let time_server_socket = UdpSocket::bind(&server_addr)
            .await
            .map_err(FatalError::UdpServerBindError)?;

        watch(
            state.clone(),
            ntske_server_task(state.clone(), ntske_server_socket),
            "NTS-KE server",
        )
        .await;
        watch(
            state.clone(),
            time_server_task(state.clone(), time_server_socket),
            "time server",
        )
        .await;
    }

    /* Bind client socket and spawn assoicated tasks */
    if !state.cfg.peers.is_empty() {
        let time_client_socket = Arc::new(
            UdpSocket::bind(&net::SocketAddr::new(
                net::IpAddr::V6(net::Ipv6Addr::UNSPECIFIED),
                0,
            ))
            .await
            .map_err(FatalError::UdpClientBindError)?,
        );

        watch(
            state.clone(),
            tick_task(state.clone(), resolver, time_client_socket.clone()),
            "tick handler",
        )
        .await;
        watch(
            state.clone(),
            time_response_task(state.clone(), time_client_socket),
            "time response handler",
        )
        .await;
    } else {
        watch(
            state.clone(),
            single_node_tick_task(state.clone()),
            "single-node tick handler",
        )
        .await;
    }

    info!("Started");

    /* Wait for a shutdown signal and then exit */
    shutdown_receiver.recv().await.unwrap()
}

///Spawn the provided task, then spawn another task that supervises its join handle
/// and signals for shutdown if it errored or panicked
async fn watch<F: Future<Output = io::Result<()>> + Send + 'static>(
    state: Arc<GlobalState>,
    f: F,
    task_desc: &'static str,
) {
    let join_handle = tokio::spawn(f);
    tokio::spawn(async move {
        match join_handle.await {
            Ok(Ok(())) => (),
            Ok(Err(e)) => {
                error!(
                    "Bailing out due to IO error in child task '{}': {}",
                    task_desc, e
                );
                state
                    .shutdown_sender
                    .send(Err(FatalError::ChildTaskError(e)))
                    .unwrap_or(());
            }
            Err(e) => {
                //Cancellations are benign, it just means the runtime
                // is shutting down.  Usually the watcher task will
                // get shut down as well before it ever gets far
                // enough to observe the JoinError, but according to
                // https://github.com/tokio-rs/tokio/issues/2077#issuecomment-572671950
                // this isn't guaranteed. Scraping the error's
                // to_string() to determine whether it's a
                // cancellation or something else is super ugly, but
                // right now it's all that's available.  I've
                // submitted
                // https://github.com/tokio-rs/tokio/pull/2051 in
                // order to have something cleaner, but as of this
                // comment it hasn't yet been merged.
                if e.to_string() != "cancelled" {
                    error!(
                        "Bailing out due to join error in child task '{}': {}",
                        task_desc, e
                    );
                    state
                        .shutdown_sender
                        .send(Err(FatalError::ChildTaskJoinError(e)))
                        .unwrap_or(());
                }
            }
        }
    });
}

///Task for serving NTS-KE requests
async fn ntske_server_task(state: Arc<GlobalState>, listener: TcpListener) -> io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((tcp_stream, peer_addr)) => {
                let child_state = state.clone();
                tokio::spawn(time::timeout(time::Duration::new(5, 0), async move {
                    let (master_key_id, master_key) =
                        child_state.secret_store.get_cached_current_master_key();
                    match child_state
                        .cfg
                        .tls_acceptor
                        .clone()
                        .accept(tcp_stream)
                        .await
                    {
                        Ok(mut tls_stream) => {
                            match ntske::serve_ntske(master_key, master_key_id, &mut tls_stream)
                                .await
                            {
                                Ok(()) => debug!("Successful NTS-KE session with {}", peer_addr),
                                Err(e) => debug!("In NTS-KE session with {}: {}", peer_addr, e),
                            }
                        }
                        Err(e) => debug!("In NTS-KE handshake with {}: {}", peer_addr, e),
                    }
                }));
            }
            //Yes, this is non-fatal. accept(2) can return errors for
            // a lot of silly, transient reasons like EHOSTUNREACH
            Err(e) => debug!("Accepting a TCP connection: {}", e),
        }
    }
}

///Task for serving response to time requests
async fn time_server_task(state: Arc<GlobalState>, mut socket: UdpSocket) -> io::Result<()> {
    time_server::serve_time(&mut socket, &state.core_state, &state.secret_store).await
}

///Task for sending out time requests every polling interval
async fn tick_task(
    state: Arc<GlobalState>,
    resolver: Arc<trust_dns_resolver::TokioAsyncResolver>,
    socket: Arc<tokio::net::UdpSocket>,
) -> io::Result<()> {
    if state.cfg.peers.is_empty() {
        return Ok(());
    }
    let tick_period =
        time::Duration::from_secs_f64(state.cfg.poll_interval / state.cfg.peers.len() as f64);
    let mut interval = time::interval(tick_period);

    let peers: Vec<PeerName> = state.cfg.peers.keys().cloned().collect();
    let mut next_peer = 0;
    loop {
        interval.tick().await;
        debug!("Tick!");

        /* Round-robin cycle through list of peers */
        let peer_name = &peers[next_peer];
        if next_peer == peers.len() - 1 {
            next_peer = 0;
        } else {
            next_peer += 1;
        }

        let peer_config = state.cfg.peers.get(&peer_name).unwrap().clone();
        let my_state = state.clone();
        let my_peer_name = peer_name.clone();
        let my_resolver = resolver.clone();
        let my_socket = socket.clone();

        tokio::spawn(async move {
            time_client::send_time_request(
                &my_resolver,
                my_socket.as_ref(),
                &my_peer_name,
                &peer_config,
                &my_state.core_state,
                &my_state.secret_store,
            )
            .await
            .unwrap_or_else(|e| {
                log!(e.level(), "On tick for peer '{}': {}", my_peer_name, e);
            })
        });
    }
}

async fn single_node_tick_task(state: Arc<GlobalState>) -> io::Result<()> {
    let tick_period = time::Duration::from_secs(1);
    let mut interval = time::interval(tick_period);

    loop {
        interval.tick().await;
        state.core_state.write().unwrap().on_single_node_tick()?;
    }
}

///Task for handling incoming responses to our time queries
async fn time_response_task(
    state: Arc<GlobalState>,
    receiver: Arc<tokio::net::UdpSocket>,
) -> io::Result<()> {
    time_client::time_response_listener(receiver.as_ref(), &state.core_state, &state.secret_store)
        .await
}

///Task for periodically updating our real-time offset
async fn update_real_offset_task(state: Arc<GlobalState>) -> io::Result<()> {
    let tick_period = time::Duration::new(64, 0);
    let mut interval = time::interval(tick_period);
    loop {
        interval.tick().await;
        debug!("Updating real offset");
        state
            .core_state
            .write()
            .unwrap()
            .update_real_offset()
            .map_err(io::Error::from)?;
    }
}

///SIGINT/SIGTERM handler
async fn shutdown_signal_task(
    state: Arc<GlobalState>,
    sig_kind: SignalKind,
    signame: &'static str,
) -> io::Result<()> {
    let mut signal_stream = signal(sig_kind)?;

    signal_stream.recv().await;
    info!("Received {}, shutting down", signame);
    state.shutdown_sender.send(Ok(())).unwrap_or(());
    Ok(())
}

///SIGHUP handler
async fn logrotate_signal_task(
    log_handle: LogHandle,
    state: Arc<GlobalState>,
    sig_kind: SignalKind,
    signame: &'static str,
) -> io::Result<()> {
    let mut signal_stream = signal(sig_kind)?;

    loop {
        signal_stream.recv().await;
        info!("{} received, reinitializing logging", signame);
        reinit_logging(
            &state.cfg.logging,
            state.cfg.log_format.as_ref().map(|s| s.as_str()),
            &log_handle,
        )?;
        info!("Logging reinitialized");
    }
}
