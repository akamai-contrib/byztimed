//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//! NTS cookie handling

use crate::aead::*;
use crate::ntske::AEAD_ALGORITHM_AES_SIV_CMAC_256;
use crate::wire::{Cookie, UnwrappedCookie};
use prost::Message;
use rand::{CryptoRng, RngCore};

///Plaintext contents of a cookie
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CookieData {
    ///The client-to-server key
    pub c2s: Aes128SivKey,
    ///The server-to-client key
    pub s2c: Aes128SivKey,
}

///Decrypt a cookie, using the given callback to look up the master key by its ID.
pub fn open_cookie<C: AsRef<[u8]>, F: FnOnce(u32) -> Option<Aes128SivKey>>(
    cookie: C,
    get_master_key: F,
) -> Option<CookieData> {
    let cookie_msg = Cookie::decode(cookie.as_ref()).ok()?;
    let master_key = get_master_key(cookie_msg.key_id)?;

    let aead = Aes128SivAead::new(&master_key);
    let plaintext = aead
        .decrypt(
            Aes128SivNonce::try_from_slice(&cookie_msg.nonce).ok()?,
            cookie_msg.ciphertext.as_slice(),
        )
        .ok()?;

    let unwrapped_cookie = UnwrappedCookie::decode(plaintext.as_ref()).ok()?;

    if unwrapped_cookie.alg_id != AEAD_ALGORITHM_AES_SIV_CMAC_256.0 as u32 {
        return None;
    }

    Some(CookieData {
        c2s: Aes128SivKey::try_clone_from_slice(unwrapped_cookie.c2s.as_slice()).ok()?,
        s2c: Aes128SivKey::try_clone_from_slice(unwrapped_cookie.s2c.as_slice()).ok()?,
    })
}

///Encrypt a cookie using the given master key
pub fn seal_cookie<R: RngCore + CryptoRng>(
    cookie_data: &CookieData,
    master_key: &Aes128SivKey,
    master_key_id: u32,
    rand: &mut R,
) -> Vec<u8> {
    let aead = Aes128SivAead::new(master_key);

    let unwrapped_cookie = UnwrappedCookie {
        alg_id: AEAD_ALGORITHM_AES_SIV_CMAC_256.0 as u32,
        c2s: Vec::from(cookie_data.c2s.as_slice()),
        s2c: Vec::from(cookie_data.s2c.as_slice()),
    };

    let mut plaintext = Vec::with_capacity(unwrapped_cookie.encoded_len());
    unwrapped_cookie
        .encode(&mut plaintext)
        .expect("Failed to serialize cookie plaintext");

    let mut nonce = Aes128SivNonce::default();
    rand.fill_bytes(nonce.as_mut_slice());

    let ciphertext = aead
        .encrypt(&nonce, plaintext.as_slice())
        .expect("Failed to encrypt cookie");

    let cookie = Cookie {
        nonce: nonce.to_vec(),
        key_id: master_key_id,
        ciphertext,
    };

    let mut out = Vec::with_capacity(cookie.encoded_len());
    cookie
        .encode(&mut out)
        .expect("Failed to serialize cookie ciphertext");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;
    use quickcheck_macros::quickcheck;

    #[derive(Debug, Clone)]
    struct ArbitraryKey(Aes128SivKey);

    impl Arbitrary for ArbitraryKey {
        fn arbitrary<G: Gen>(g: &mut G) -> ArbitraryKey {
            let mut key = Aes128SivKey::default();
            g.fill_bytes(&mut key);
            ArbitraryKey(key)
        }
    }

    impl Arbitrary for CookieData {
        fn arbitrary<G: Gen>(g: &mut G) -> CookieData {
            CookieData {
                c2s: ArbitraryKey::arbitrary(g).0,
                s2c: ArbitraryKey::arbitrary(g).0,
            }
        }
    }

    #[quickcheck]
    fn round_trip(unwrapped: CookieData, master_key: ArbitraryKey, key_id: u32) -> bool {
        let mut rng = rand::thread_rng();
        let get_key = |id| {
            if id == key_id {
                Some(master_key.0)
            } else {
                None
            }
        };

        open_cookie(
            &seal_cookie(&unwrapped, &master_key.0, key_id, &mut rng),
            get_key,
        ) == Some(unwrapped)
    }

    #[quickcheck]
    fn bad_cookie(cookie: Vec<u8>, master_key: ArbitraryKey) -> bool {
        let get_key = |_| Some(master_key.0);

        open_cookie(&cookie.as_slice(), get_key) == None
    }
}
