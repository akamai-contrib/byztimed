//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//! Configuration representation and configuration file parsing

use crate::logging::LogConfig;
use crate::ntske;
use crate::peer_name::PeerName;
use serde::Deserialize;
use serde_json as cfgformat;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::vec::Vec;
use tokio_rustls::rustls;
use tokio_rustls::webpki::{DNSName, DNSNameRef};

///Default port number. Set to 0 until we have an IANA allocation,
/// which is treated as making it mandatory to configure.
const DEFAULT_PORT: u16 = 0;

///Default polling interval in seconds
const DEFAULT_POLL_INTERVAL: f64 = 8.0;

///Default upper bound on clock drift rate, in parts per billion
const DEFAULT_DRIFT_PPB: i64 = 250_000;

///Contents of a peer entry in the config file, rawly deserialized
/// from serde.
#[derive(Debug, Clone, Deserialize)]
struct RawPeerConfig {
    host: String,
    port: Option<u16>,
    dist: Option<i64>,
    cert_name: Option<String>,
    authorities: Option<String>,
}

///Enumeration of log levels that can appear as values in the
/// `logging` map. Isomorphic to `log::LevelFilter`, but we need our
/// own version so we can derive `Deserialize` for it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawLevelFilter {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

///Top-level contents of the config file, rawly deserialized from
/// serde.
#[derive(Debug, Clone, Deserialize)]
struct RawConfig {
    timedata: String,
    secret_store: String,
    logging: Option<HashMap<String, RawLevelFilter>>,
    log_format: Option<String>,
    ro_mode: Option<bool>,
    bind_host: Option<String>,
    bind_port: Option<u16>,
    poll_interval: Option<f64>,
    drift_ppb: Option<i64>,
    key: Option<String>,
    cert: Option<String>,
    authorities: Option<String>,
    peers: HashMap<String, RawPeerConfig>,
}

impl Into<log::LevelFilter> for RawLevelFilter {
    fn into(self) -> log::LevelFilter {
        match self {
            RawLevelFilter::Error => log::LevelFilter::Error,
            RawLevelFilter::Warn => log::LevelFilter::Warn,
            RawLevelFilter::Info => log::LevelFilter::Info,
            RawLevelFilter::Debug => log::LevelFilter::Debug,
            RawLevelFilter::Trace => log::LevelFilter::Trace,
        }
    }
}

///"Cooked" version of a peer entry, semantically validated and with
/// defaults filled in
#[derive(Clone)]
pub struct PeerConfig {
    ///Hostname at which to contact this peer
    pub host: String,
    ///Port on which to contact this peer
    pub port: u16,
    ///Lower bound on peer's physical distance in meters
    pub dist: i64,
    ///Subject DNS name to expect when validating the peer's X.509
    /// certificate
    pub cert_name: DNSName,
    ///Connector for NTS-KE client sessions
    pub tls_connector: tokio_rustls::TlsConnector,
}

///"Cooked" representation of a configuration, semantically validated and with
/// defaults filled in
#[derive(Clone)]
pub struct Config {
    ///Path to the timedata file
    pub timedata: PathBuf,
    ///Path to the secret store
    pub secret_store: PathBuf,
    ///Vector of logging targets
    pub logging: Vec<LogConfig>,
    ///Log format string
    pub log_format: Option<String>,
    ///Whether we're running in read-only mode
    pub ro_mode: bool,
    ///Host address to bind the server to
    pub bind_host: net::IpAddr,
    ///Port to bind the server to
    pub bind_port: u16,
    ///Polling interval in seconds
    pub poll_interval: f64,
    ///Upper bound on clock drift rate in parts per billion
    pub drift_ppb: i64,
    ///Acceptor for NTS-KE server sessions
    pub tls_acceptor: tokio_rustls::TlsAcceptor,
    ///Map of peers to their configuraitons
    pub peers: HashMap<PeerName, Arc<PeerConfig>>,
}

///A semantic error in the configuration file
#[derive(Clone, Debug)]
pub struct SemanticError {
    ///Name of the peer entry to which this error pertains, or `None` for the global section
    pub section: Option<PeerName>,
    ///Text of the error message
    pub text: &'static str,
}

///An error in the configuration file
#[derive(Debug)]
pub enum ConfigError {
    Syntactic(cfgformat::Error),
    Semantic(Vec<SemanticError>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConfigError::*;
        match self {
            Syntactic(e) => write!(f, "Syntax error in configuration file: {}", e),
            Semantic(evec) => {
                for e in evec {
                    match &e.section {
                        Some(section) => {
                            write!(f, "In configuration of peer '{}': {}", section, e.text)?
                        }
                        None => write!(f, "In global section of configuration file: {}", e.text)?,
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

fn make_tls_client_config<Authorities: AsRef<str>>(
    authorities_path: &Authorities,
    section: Option<&PeerName>,
    errors: &mut Vec<SemanticError>,
) -> rustls::ClientConfig {
    let mut store = rustls::RootCertStore::empty();

    match fs::File::open(Path::new(authorities_path.as_ref())) {
        Ok(f) => {
            let mut bufreader = std::io::BufReader::new(f);
            match store.add_pem_file(&mut bufreader) {
                Ok((valid, invalid)) => {
                    if valid == 0 {
                        if invalid == 0 {
                            errors.push(SemanticError {
                                section: section.cloned(),
                                text: "`authorities` file contains no certificate authorities",
                            })
                        } else {
                            errors.push(SemanticError {
                                section: section.cloned(),
                                text: "`authorities` file contains only invalid certificate authorities"
                            })
                        }
                    }
                }
                Err(_) => errors.push(SemanticError {
                    section: section.cloned(),
                    text: "`authorities` file is not a valid PEM file",
                }),
            }
        }
        Err(_) => errors.push(SemanticError {
            section: section.cloned(),
            text: "`authorities` file could not be opened",
        }),
    }

    let mut tls_config = rustls::ClientConfig::new();
    tls_config.root_store = store;
    tls_config.alpn_protocols = vec![ntske::NTSKE_ALPN.to_vec()];
    tls_config
}

///Semantically validate a parsed configuration and fill in defaults
fn cook_config(raw: RawConfig) -> Result<Config, Vec<SemanticError>> {
    let mut errors: Vec<SemanticError> = Vec::new();

    let bind_host = match raw.bind_host {
        Some(ip) => ip.parse().unwrap_or_else(|_| {
            errors.push(SemanticError {
                section: None,
                text: "`bind_host` must be an IP address",
            });
            net::IpAddr::V6(net::Ipv6Addr::UNSPECIFIED)
        }),
        None => net::IpAddr::V6(net::Ipv6Addr::UNSPECIFIED),
    };
    let bind_port = raw.bind_port.unwrap_or(DEFAULT_PORT);
    let poll_interval = raw.poll_interval.unwrap_or(DEFAULT_POLL_INTERVAL);
    let drift_ppb = raw.drift_ppb.unwrap_or(DEFAULT_DRIFT_PPB);
    let ro_mode = raw.ro_mode.unwrap_or(false);

    let rawlogging = raw.logging.unwrap_or_else(|| {
        let mut h = HashMap::new();
        h.insert(String::from("STDOUT"), RawLevelFilter::Info);
        h
    });

    let mut logging = Vec::with_capacity(rawlogging.len());
    logging.extend(rawlogging.into_iter().map(|(k, rawlevel)| {
        let level = rawlevel.into();
        if k.as_str() == "STDOUT" {
            LogConfig::ConsoleLog(log4rs::append::console::Target::Stdout, level)
        } else if k.as_str() == "STDERR" {
            LogConfig::ConsoleLog(log4rs::append::console::Target::Stderr, level)
        } else {
            LogConfig::FileLog(PathBuf::from(k), level)
        }
    }));

    if !ro_mode && bind_port == 0 {
        errors.push(SemanticError {
            section: None,
            text: "`bind_port` must be provided when not in ro_mode",
        });
    }

    let global_client_tls_config = raw
        .authorities
        .map(|authorities| Arc::new(make_tls_client_config(&authorities, None, &mut errors)));

    if !ro_mode && (raw.key.is_none() || raw.cert.is_none()) {
        errors.push(SemanticError {
            section: None,
            text: "`cert` and `key` must be provided when not in ro_mode",
        });
    }

    let mut server_tls_config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    server_tls_config.alpn_protocols = vec![ntske::NTSKE_ALPN.to_vec()];

    if let (Some(cert_path), Some(key_path)) = (raw.cert, raw.key) {
        let maybe_certs = fs::File::open(Path::new(&cert_path))
            .map_err(|_| {
                errors.push(SemanticError {
                    section: None,
                    text: "`cert` file could not be opened",
                })
            })
            .and_then(|f| {
                let mut bufreader = std::io::BufReader::new(f);
                rustls::internal::pemfile::certs(&mut bufreader).map_err(|()| {
                    errors.push(SemanticError {
                        section: None,
                        text: "`cert` file does not contain valid PEM",
                    })
                })
            });

        let maybe_keys = fs::File::open(Path::new(&key_path))
            .map_err(|_| {
                errors.push(SemanticError {
                    section: None,
                    text: "`key` file could not be opened",
                })
            })
            .and_then(|f| {
                let mut bufreader = std::io::BufReader::new(f);
                rustls::internal::pemfile::pkcs8_private_keys(&mut bufreader).map_err(|()| {
                    errors.push(SemanticError {
                        section: None,
                        text: "`key` file does not contain valid PEM",
                    })
                })
            });

        if let (Ok(certs), Ok(mut keys)) = (maybe_certs, maybe_keys) {
            if let Some(key) = keys.pop() {
                if server_tls_config.set_single_cert(certs, key).is_err() {
                    errors.push(SemanticError {
                        section: None,
                        text: "`key` file is not valid PKCS#8",
                    })
                }
            } else {
                errors.push(SemanticError {
                    section: None,
                    text: "`key` file does not contain any PKCS#8-encoded keys (your key may be in the wrong format; see manual for more info)"
                })
            }
        }
    } else if !ro_mode {
        errors.push(SemanticError {
            section: None,
            text: "`cert` and `key` must be provided when not in ro_mode",
        });
    }

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls_config));

    let mut peers = HashMap::with_capacity(raw.peers.len());

    for (peer_name_string, rawpeer) in raw.peers {
        let peer_name = PeerName::new(peer_name_string);
        let host = rawpeer.host;
        let port = rawpeer.port.unwrap_or_else(|| {
            if DEFAULT_PORT == 0 {
                errors.push(SemanticError {
                    section: Some(peer_name.clone()),
                    text: "A `port` must be specified for each peer",
                });
            };
            DEFAULT_PORT
        });

        let dist = rawpeer.dist.unwrap_or(0);
        let cert_name_string = rawpeer.cert_name.unwrap_or_else(|| host.clone());
        let cert_name = DNSNameRef::try_from_ascii_str(cert_name_string.as_str())
            .unwrap_or_else(|_| {
                errors.push(SemanticError {
                    section: Some(peer_name.clone()),
                    text: "`cert_name` is not a syntactically-valid DNS name",
                });
                DNSNameRef::try_from_ascii_str("bogus.invalid").unwrap()
            })
            .to_owned();

        let client_tls_config = match rawpeer.authorities {
            Some(authorities) => Arc::new(make_tls_client_config(
                &authorities,
                Some(&peer_name),
                &mut errors,
            )),
            None => match &global_client_tls_config {
                Some(client_tls_config) => client_tls_config.clone(),
                None => {
                    errors.push(SemanticError {
                        section: Some(peer_name.clone()),
                        text: "No `authorities` was specified for this peer and no global default was given",
                    });
                    Arc::new(rustls::ClientConfig::new())
                }
            },
        };

        let tls_connector = tokio_rustls::TlsConnector::from(client_tls_config);

        peers.insert(
            peer_name,
            Arc::new(PeerConfig {
                host,
                port,
                dist,
                cert_name,
                tls_connector,
            }),
        );
    }

    if errors.is_empty() {
        Ok(Config {
            timedata: PathBuf::from(raw.timedata),
            secret_store: PathBuf::from(raw.secret_store),
            logging,
            log_format: raw.log_format,
            ro_mode,
            bind_host,
            bind_port,
            poll_interval,
            drift_ppb,
            tls_acceptor,
            peers,
        })
    } else {
        Err(errors)
    }
}

impl Config {
    ///Parse and validate a configuration and return the parsed result
    pub fn parse<S: AsRef<str>>(config: S) -> Result<Config, ConfigError> {
        cook_config(cfgformat::from_str(config.as_ref()).map_err(ConfigError::Syntactic)?)
            .map_err(ConfigError::Semantic)
    }
}
