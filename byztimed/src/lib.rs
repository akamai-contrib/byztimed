//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//! THIS CRATE IS NOT A LIBRARY.
//!
//! The API exposed by this crate is intended only for internal use
//! by the `byztimed` binary and carries no stability guarantees
//! whatsoever. See <https://github.com/akamai-contrib/byztimed> for
//! user documentation. This crate is semantically versioned on the
//! format of its configuration file and wire protocol. That is, it
//! will interoperate with peers running compatible versions, and
//! minor version bumps should not require the user to make any
//! changes to the configuration file.

pub mod aead;
pub mod config;
pub mod core;
pub mod logging;
///Generated code for serializing and deserializing Byztime's protobuf-based wire format
pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/byztimed.wire.rs"));
    ///The amount of padding, in addition to space needed for extra
    /// cookies, that has to be added to a request to make it equal in
    /// length to the anticpated response
    pub const EXTRA_PADDING: usize = 39;
}
pub mod cookie;
pub mod ntske;
pub mod peer_name;
pub mod store;
pub mod time_client;
pub mod time_server;

#[cfg(test)]
mod time_test;
