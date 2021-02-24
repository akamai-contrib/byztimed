//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//!Secret store
//!
//!This module manages the secret store, which is a cache of
//! cryptographic credentials used for NTS. It stores session keys
//! (C2S and S2C keys), cookies, and the master keys used to encrypt
//! cookies. It's backed by [rkv](../../rkv/index.html) which is in
//! turn backed by [LMDB](https://symas.com/lmdb/), but provides an
//! interface which mostly abstracts this away. The only exposed
//! implementation detail is rkv's `StoreError` type.

//General note on locking throughout this module: in theory, several methods of
// `SecretStore` touch the filesystem and could block, and therefore ought to
// implemented as futures. Server operations typically don't touch the database
// at all (working from the master key cache instead) and at worst perform a read.
// Client operations only happen once per tick, so barring massive disk contention
// plus a very poor IO scheduler, one should finish before the next one begins,
// so we're only ever blocking one worker thread.

use crate::aead::keygen;
use crate::aead::*;
use crate::peer_name::PeerName;
use bincode;
use rkv::value::Type;
use rkv::{DataError, StoreOptions, Value};
use serde::{Deserialize, Serialize};
use std::mem::drop;
use std::path::Path;
use std::sync::{Arc, RwLock};

type Rkv = rkv::Rkv<rkv::backend::LmdbEnvironment>;
type Manager = rkv::Manager<rkv::backend::LmdbEnvironment>;
type SingleStore = rkv::SingleStore<rkv::backend::LmdbDatabase>;

///Convenience re-export of [rkv::StoreError](../../rkv/error/enum.StoreError.html)
pub use rkv::StoreError;

///We serialize this enum using bincode to form our keys for rkv
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
enum StoreKey<'s> {
    CurrentMasterKeyIndex,
    MasterKey(u32),
    C2SKey(&'s str),
    S2CKey(&'s str),
    Cookies(&'s str),
}

impl<'s> StoreKey<'s> {
    fn serialize(&self) -> Result<Vec<u8>, StoreError> {
        bincode::serialize(self).map_err(|e| StoreError::DataError(DataError::EncodingError(e)))
    }
}

fn serialize_cookies(cookies: &[Vec<u8>]) -> Result<Vec<u8>, StoreError> {
    bincode::serialize(cookies).map_err(|e| StoreError::DataError(DataError::EncodingError(e)))
}

///Extension trait to fix an annoying omission in rkv. See <https://github.com/mozilla/rkv/issues/186>
trait SingleStoreExt {
    fn delete_if_present<K: AsRef<[u8]>>(
        self,
        writer: &mut rkv::Writer<rkv::backend::LmdbRwTransaction>,
        k: K,
    ) -> Result<bool, StoreError>;
}

impl SingleStoreExt for SingleStore {
    fn delete_if_present<K: AsRef<[u8]>>(
        self,
        writer: &mut rkv::Writer<rkv::backend::LmdbRwTransaction>,
        k: K,
    ) -> Result<bool, StoreError> {
        match self.delete(writer, k) {
            Ok(()) => Ok(true),
            Err(StoreError::LmdbError(lmdb::Error::NotFound)) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

///Cache of the current and previous master key
///
///Master key lookups are on the critical path of serving timetstamps so we want
///them to be fast and as close to constant-time as possible. So we use this
///structure to cache them rather than calling into rkv every time and possibly
///even touching disk.
#[derive(Debug, Clone)]
struct MasterKeyCache {
    current_master_key_index: u32,
    current_master_key: Aes128SivKey,
    previous_master_key: Aes128SivKey,
}

///Interface to the on-filesystem secret store
///
///All our methods return StoreError. These might be propagated from
/// inside `rkv`, but in some cases we construct them ourselves,
/// abusing the existing error types slightly to communicate semantic
/// errors in our own data. Such errors should never happen unless we
/// either have a bug, or some other program has corrupted the store.
pub struct SecretStore {
    env_arc: Arc<RwLock<Rkv>>,
    store: SingleStore,
    cache: RwLock<MasterKeyCache>,
}

///Silly helper function that really ought to already be in rkv
fn get_rkv_type(v: &Value) -> Type {
    match v {
        Value::Bool(_) => Type::Bool,
        Value::U64(_) => Type::U64,
        Value::I64(_) => Type::I64,
        Value::F64(_) => Type::F64,
        Value::Instant(_) => Type::Instant,
        Value::Uuid(_) => Type::Uuid,
        Value::Str(_) => Type::Str,
        Value::Json(_) => Type::Json,
        Value::Blob(_) => Type::Blob,
    }
}

const MAX_COOKIES: usize = 16;

impl SecretStore {
    ///Open the secret store at the location given in the configuration
    pub fn new<P: AsRef<Path>>(path: &P) -> Result<SecretStore, StoreError> {
        //Open the database and begin a read-write transaction
        let env_arc = Manager::singleton()
            .write()
            .unwrap()
            .get_or_create(path.as_ref(), rkv::Rkv::new::<rkv::backend::Lmdb>)?;
        let env = env_arc.read().unwrap();
        let store = env.open_single("byztimed_secrets", StoreOptions::create())?;
        let mut writer = env.write()?;

        //Look up the entries that should populate our master key cache
        let current_master_key_index =
            store.get(&writer, StoreKey::CurrentMasterKeyIndex.serialize()?)?;
        let current_master_key = match current_master_key_index {
            Some(Value::U64(index)) => {
                store.get(&writer, StoreKey::MasterKey(index as u32).serialize()?)?
            }
            _ => Option::None,
        };
        let previous_master_key = match current_master_key_index {
            Some(Value::U64(index)) => store.get(
                &writer,
                StoreKey::MasterKey(index.wrapping_sub(1) as u32).serialize()?,
            )?,
            _ => Option::None,
        };

        //If these values are all present and good, populate the cache with them
        let maybe_master_key_cache = match (
            current_master_key_index,
            current_master_key,
            previous_master_key,
        ) {
            (Some(Value::U64(index)), Some(Value::Blob(cmk)), Some(Value::Blob(pmk))) => {
                match (
                    Aes128SivKey::try_clone_from_slice(cmk),
                    Aes128SivKey::try_clone_from_slice(pmk),
                ) {
                    (Ok(cmk_arr), Ok(pmk_arr)) => Some(MasterKeyCache {
                        current_master_key_index: index as u32,
                        current_master_key: cmk_arr,
                        previous_master_key: pmk_arr,
                    }),
                    _ => None,
                }
            }
            _ => None,
        };

        //Otherwise, (re)initialize them and populate the cache with
        // the keys we've just generated.
        let master_key_cache = match maybe_master_key_cache {
            Some(cache) => cache,
            None => {
                let mut rng = rand::thread_rng();
                let cmk_vec = keygen(&mut rng);
                let pmk_vec = keygen(&mut rng);

                store.put(
                    &mut writer,
                    StoreKey::CurrentMasterKeyIndex.serialize()?,
                    &Value::U64(1),
                )?;
                store.put(
                    &mut writer,
                    StoreKey::MasterKey(0).serialize()?,
                    &Value::Blob(pmk_vec.as_slice()),
                )?;
                store.put(
                    &mut writer,
                    StoreKey::MasterKey(1).serialize()?,
                    &Value::Blob(cmk_vec.as_slice()),
                )?;

                MasterKeyCache {
                    current_master_key_index: 1,
                    current_master_key: cmk_vec,
                    previous_master_key: pmk_vec,
                }
            }
        };
        writer.commit()?;
        drop(env);

        Ok(SecretStore {
            env_arc,
            store,
            cache: RwLock::new(master_key_cache),
        })
    }

    ///Look up the current master key index from the store
    pub fn get_current_master_key_index(&self) -> Result<u32, StoreError> {
        let store_key = StoreKey::CurrentMasterKeyIndex.serialize()?;
        let env = self.env_arc.read().unwrap();
        let reader = env.read()?;
        let store_value = self.store.get(&reader, store_key)?;

        match store_value {
            Some(Value::U64(index)) => Ok(index as u32),
            Some(v) => Err(StoreError::DataError(DataError::UnexpectedType {
                expected: Type::U64,
                actual: get_rkv_type(&v),
            })),
            None => Err(StoreError::DataError(DataError::Empty)),
        }
    }

    ///Look up the current master key and index from our cache
    pub fn get_cached_current_master_key(&self) -> (u32, Aes128SivKey) {
        let cache = self.cache.read().unwrap();
        (cache.current_master_key_index, cache.current_master_key)
    }

    ///Look up the master key with the given index from the cache
    pub fn get_cached_master_key(&self, index: u32) -> Option<Aes128SivKey> {
        let cache = self.cache.read().unwrap();
        if index == cache.current_master_key_index {
            Some(cache.current_master_key)
        } else if index == cache.current_master_key_index.wrapping_sub(1) {
            Some(cache.previous_master_key)
        } else {
            None
        }
    }

    ///Look up the master key with the given index, from cache if
    /// possible, otherwise from disk
    pub fn get_master_key(&self, index: u32) -> Result<Option<Aes128SivKey>, StoreError> {
        let cache = self.cache.read().unwrap();
        if index == cache.current_master_key_index {
            Ok(Some(cache.current_master_key))
        } else if index == cache.current_master_key_index.wrapping_sub(1) {
            Ok(Some(cache.previous_master_key))
        } else {
            let store_key = StoreKey::MasterKey(index).serialize()?;
            let env = self.env_arc.read().unwrap();
            let reader = env.read()?;
            let store_value = self.store.get(&reader, store_key)?;
            match store_value {
                Some(Value::Blob(b)) => Ok(Some(Aes128SivKey::try_clone_from_slice(b).map_err(
                    |_| {
                        StoreError::DataError(DataError::DecodingError {
                            value_type: Type::Blob,
                            err: Box::new(bincode::ErrorKind::Custom(
                                "Master key has wrong length".to_string(),
                            )),
                        })
                    },
                )?)),
                Some(v) => Err(StoreError::DataError(DataError::UnexpectedType {
                    expected: Type::Blob,
                    actual: get_rkv_type(&v),
                })),
                None => Ok(None),
            }
        }
    }

    ///Generate a new master key and update disk and cache
    pub fn rotate_master_key(&self) -> Result<(), StoreError> {
        let env = self.env_arc.read().unwrap();
        let mut writer = env.write()?;
        let current_index = self
            .store
            .get(&writer, StoreKey::CurrentMasterKeyIndex.serialize()?)?;
        let (old_key, new_index, delete_index) = match current_index {
            Some(Value::U64(index)) => match self
                .store
                .get(&writer, StoreKey::MasterKey(index as u32).serialize()?)?
            {
                Some(Value::Blob(old_key_slice)) => {
                    let old_key =
                        Aes128SivKey::try_clone_from_slice(old_key_slice).map_err(|_| {
                            StoreError::DataError(DataError::DecodingError {
                                value_type: Type::Blob,
                                err: Box::new(bincode::ErrorKind::Custom(
                                    "Master key has wrong length".to_string(),
                                )),
                            })
                        })?;
                    Ok((
                        old_key,
                        (index as u32).wrapping_add(1),
                        (index as u32).wrapping_sub(1),
                    ))
                }
                Some(v) => Err(StoreError::DataError(DataError::UnexpectedType {
                    expected: Type::Blob,
                    actual: get_rkv_type(&v),
                })),
                None => Err(StoreError::DataError(DataError::Empty)),
            },
            Some(v) => Err(StoreError::DataError(DataError::UnexpectedType {
                expected: Type::U64,
                actual: get_rkv_type(&v),
            })),
            None => Err(StoreError::DataError(DataError::Empty)),
        }?;

        let mut rng = rand::thread_rng();
        let new_key = keygen(&mut rng);
        self.store
            .delete_if_present(&mut writer, StoreKey::MasterKey(delete_index).serialize()?)?;
        self.store.put(
            &mut writer,
            StoreKey::MasterKey(new_index).serialize()?,
            &Value::Blob(new_key.as_slice()),
        )?;
        self.store.put(
            &mut writer,
            StoreKey::CurrentMasterKeyIndex.serialize()?,
            &Value::U64(new_index as u64),
        )?;
        writer.commit()?;

        let mut cache = self.cache.write().unwrap();
        *cache = MasterKeyCache {
            current_master_key_index: new_index,
            current_master_key: new_key,
            previous_master_key: old_key,
        };

        Ok(())
    }

    ///Look up the C2S key for the given peer
    pub fn get_c2s_key(&self, peer_name: &PeerName) -> Result<Option<Aes128SivKey>, StoreError> {
        let env = self.env_arc.read().unwrap();
        let reader = env.read()?;
        match self
            .store
            .get(&reader, StoreKey::C2SKey(peer_name.as_ref()).serialize()?)?
        {
            Some(Value::Blob(b)) => Ok(Some(Aes128SivKey::try_clone_from_slice(b).map_err(
                |_| {
                    StoreError::DataError(DataError::DecodingError {
                        value_type: Type::Blob,
                        err: Box::new(bincode::ErrorKind::Custom(
                            "C2S key has wrong length".to_string(),
                        )),
                    })
                },
            )?)),
            Some(v) => Err(StoreError::DataError(DataError::UnexpectedType {
                expected: Type::Blob,
                actual: get_rkv_type(&v),
            })),
            None => Ok(None),
        }
    }

    ///Set the C2S, S2C, and cookies for a peer, discarding any existing cookies
    pub fn set_credentials(
        &self,
        peer_name: &PeerName,
        c2s: &Aes128SivKey,
        s2c: &Aes128SivKey,
        cookies: &[Vec<u8>],
    ) -> Result<(), StoreError> {
        let env = self.env_arc.read().unwrap();
        let mut writer = env.write()?;
        self.store.put(
            &mut writer,
            StoreKey::C2SKey(peer_name.as_ref()).serialize()?,
            &Value::Blob(&c2s.to_vec()),
        )?;

        self.store.put(
            &mut writer,
            StoreKey::S2CKey(peer_name.as_ref()).serialize()?,
            &Value::Blob(&s2c.to_vec()),
        )?;

        let trunc_cookies = &cookies[0..std::cmp::min(MAX_COOKIES, cookies.len())];

        self.store.put(
            &mut writer,
            StoreKey::Cookies(peer_name.as_ref()).serialize()?,
            &Value::Blob(&serialize_cookies(trunc_cookies)?),
        )?;
        writer.commit()
    }

    ///Look up the S2C key for the given peer
    pub fn get_s2c_key(&self, peer_name: &PeerName) -> Result<Option<Aes128SivKey>, StoreError> {
        let env = self.env_arc.read().unwrap();
        let reader = env.read()?;
        match self
            .store
            .get(&reader, StoreKey::S2CKey(peer_name.as_ref()).serialize()?)?
        {
            Some(Value::Blob(b)) => Ok(Some(Aes128SivKey::try_clone_from_slice(b).map_err(
                |_| {
                    StoreError::DataError(DataError::DecodingError {
                        value_type: Type::Blob,
                        err: Box::new(bincode::ErrorKind::Custom(
                            "S2C key has wrong length".to_string(),
                        )),
                    })
                },
            )?)),
            Some(v) => Err(StoreError::DataError(DataError::UnexpectedType {
                expected: Type::Blob,
                actual: get_rkv_type(&v),
            })),
            None => Ok(None),
        }
    }

    ///Remove one cookie from the store for the given peer and return the cookie just removed and how many remain
    pub fn take_cookie(
        &self,
        peer_name: &PeerName,
    ) -> Result<(Option<Vec<u8>>, usize), StoreError> {
        let env = self.env_arc.write().unwrap();
        let mut writer = env.write()?;

        match self
            .store
            .get(&writer, StoreKey::Cookies(peer_name.as_ref()).serialize()?)?
        {
            Some(Value::Blob(b)) => {
                let mut cookies: Vec<Vec<u8>> = match bincode::deserialize(b) {
                    Ok(cookies) => Ok(cookies),
                    Err(e) => Err(StoreError::DataError(DataError::EncodingError(e))),
                }?;
                let taken = cookies.pop();
                self.store.put(
                    &mut writer,
                    StoreKey::Cookies(peer_name.as_ref()).serialize()?,
                    &Value::Blob(&serialize_cookies(&cookies)?),
                )?;
                writer.commit()?;
                Ok((taken, cookies.len()))
            }
            Some(v) => Err(StoreError::DataError(DataError::UnexpectedType {
                expected: Type::Blob,
                actual: get_rkv_type(&v),
            })),
            None => Ok((None, 0)),
        }
    }

    ///Insert the cookies for the given peer into the store, retaining up to a maximum of 16
    pub fn give_cookies(
        &self,
        peer_name: &PeerName,
        mut cookies: Vec<Vec<u8>>,
    ) -> Result<(), StoreError> {
        let env = self.env_arc.write().unwrap();
        let mut writer = env.write()?;

        match self
            .store
            .get(&writer, StoreKey::Cookies(peer_name.as_ref()).serialize()?)?
        {
            Some(Value::Blob(b)) => {
                let mut old_cookies: Vec<Vec<u8>> = match bincode::deserialize(b) {
                    Ok(old_cookies) => Ok(old_cookies),
                    Err(e) => Err(StoreError::DataError(DataError::EncodingError(e))),
                }?;
                cookies.append(&mut old_cookies);
                cookies.truncate(MAX_COOKIES);

                self.store.put(
                    &mut writer,
                    StoreKey::Cookies(peer_name.as_ref()).serialize()?,
                    &Value::Blob(&serialize_cookies(&cookies)?),
                )?;
                writer.commit()
            }
            Some(v) => Err(StoreError::DataError(DataError::UnexpectedType {
                expected: Type::Blob,
                actual: get_rkv_type(&v),
            })),
            None => {
                cookies.truncate(MAX_COOKIES);
                self.store.put(
                    &mut writer,
                    StoreKey::Cookies(peer_name.as_ref()).serialize()?,
                    &Value::Blob(&serialize_cookies(&cookies)?),
                )?;
                writer.commit()
            }
        }
    }

    ///Clear all credentials for the peer
    pub fn clear_peer(&self, peer_name: &PeerName) -> Result<(), StoreError> {
        let env = self.env_arc.write().unwrap();
        let mut writer = env.write()?;

        self.store.delete_if_present(
            &mut writer,
            StoreKey::Cookies(peer_name.as_ref()).serialize()?,
        )?;
        self.store.delete_if_present(
            &mut writer,
            StoreKey::S2CKey(peer_name.as_ref()).serialize()?,
        )?;
        self.store.delete_if_present(
            &mut writer,
            StoreKey::C2SKey(peer_name.as_ref()).serialize()?,
        )?;
        writer.commit()
    }
}

///A SecretStore wrapper that deletes the store when dropped
pub struct TempSecretStore {
    //The order of these members must not change, because we want
    // store to be dropped before tempdir is. Fields gets dropped
    // first to last — Rust is weird this way.
    // See <https://github.com/rust-lang/rfcs/blob/master/text/1857-stabilize-drop-order.md>
    store: SecretStore,
    _tempdir: tempfile::TempDir,
}

impl TempSecretStore {
    pub fn new() -> Result<TempSecretStore, StoreError> {
        let tempdir = tempfile::tempdir().map_err(StoreError::IoError)?;
        let store = SecretStore::new(&tempdir)?;
        Ok(TempSecretStore {
            store,
            _tempdir: tempdir,
        })
    }
}

impl AsRef<SecretStore> for TempSecretStore {
    fn as_ref(&self) -> &SecretStore {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead;
    use quickcheck::Arbitrary;
    use std::iter;
    use std::iter::FromIterator;

    #[test]
    fn key_rotation() {
        let temp_store = TempSecretStore::new().unwrap();
        let store = temp_store.as_ref();
        assert_eq!(store.get_current_master_key_index().unwrap(), 1);
        let key_1 = store.get_master_key(1).unwrap();
        store.rotate_master_key().unwrap();
        assert_eq!(store.get_current_master_key_index().unwrap(), 2);
        assert_eq!(store.get_master_key(0).unwrap(), None);
        assert_eq!(store.get_master_key(1).unwrap(), key_1);
    }

    #[test]
    fn credential_storage() {
        let temp_store = TempSecretStore::new().unwrap();
        let store = temp_store.as_ref();
        let mut g = quickcheck::StdThreadGen::new(100);
        let peer_name = PeerName::new(String::arbitrary(&mut g));
        let c2s = aead::keygen_test(&mut g);
        let s2c = aead::keygen_test(&mut g);
        let cookies = Vec::from_iter(iter::repeat_with(|| Vec::arbitrary(&mut g)).take(10));
        let first_cookies = cookies[0..8].to_vec();
        let more_cookies = cookies[8..10].to_vec();
        store
            .set_credentials(&peer_name, &c2s, &s2c, &first_cookies)
            .unwrap();
        assert_eq!(store.get_c2s_key(&peer_name).unwrap(), Some(c2s));
        assert_eq!(store.get_s2c_key(&peer_name).unwrap(), Some(s2c));
        for i in 0..4 {
            assert_eq!(
                store.take_cookie(&peer_name).unwrap().0.as_deref(),
                Some(cookies[7 - i].as_slice())
            );
        }
        store.give_cookies(&peer_name, more_cookies).unwrap();
        for i in 4..8 {
            assert_eq!(
                store.take_cookie(&peer_name).unwrap().0.as_deref(),
                Some(cookies[7 - i].as_slice())
            );
        }
        assert_eq!(
            store.take_cookie(&peer_name).unwrap().0.as_deref(),
            Some(cookies[9].as_slice())
        );
        assert_eq!(
            store.take_cookie(&peer_name).unwrap().0.as_deref(),
            Some(cookies[8].as_slice())
        );
        assert_eq!(store.take_cookie(&peer_name).unwrap().0, None);
    }
}
