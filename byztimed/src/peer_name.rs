//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//! Interned strings identifying peers

use std::cmp::Ordering;
use std::convert::{AsRef, From};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Interned string identifying a peer
//
/// A `PeerName` wraps a referece-counted string. `PeerName`'s `Eq`
/// and `Ord` instances are defined using pointer comparison. A
/// `PeerName` will compare equal to another `PeerName` that it was
/// `clone()`d from, but not to one that was constructed from a
/// different call to `PeerName::new`, even if the two are equal
/// as strings.
#[derive(Debug, Clone)]
pub struct PeerName(Arc<String>);

impl PeerName {
    pub fn new(name: String) -> PeerName {
        PeerName(Arc::new(name))
    }
}

impl From<Arc<String>> for PeerName {
    fn from(other: Arc<String>) -> PeerName {
        PeerName(other)
    }
}

impl From<PeerName> for Arc<String> {
    fn from(other: PeerName) -> Arc<String> {
        other.0
    }
}

impl AsRef<String> for PeerName {
    fn as_ref(&self) -> &String {
        self.0.as_ref()
    }
}

impl AsRef<str> for PeerName {
    fn as_ref(&self) -> &str {
        self.0.as_ref().as_ref()
    }
}

impl AsRef<[u8]> for PeerName {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().as_ref()
    }
}

impl PartialEq for PeerName {
    fn eq(&self, other: &PeerName) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for PeerName {}

impl Ord for PeerName {
    fn cmp(&self, other: &PeerName) -> Ordering {
        (self.0.as_ref() as *const String).cmp(&(other.0.as_ref() as *const String))
    }
}

impl PartialOrd for PeerName {
    fn partial_cmp(&self, other: &PeerName) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for PeerName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.0.as_ref() as *const String).hash(state)
    }
}

impl fmt::Display for PeerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.as_ref().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cloned_eq() {
        let peer1 = PeerName::new("test".into());
        let peer2 = peer1.clone();
        assert_eq!(peer1, peer2);
    }

    #[test]
    fn new_neq() {
        let peer1 = PeerName::new("test".into());
        let peer2 = PeerName::new("test".into());
        assert_ne!(peer1, peer2);
    }
}
