//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//!Convenience wrapper around the `aead` and `aes_siv` crates

pub use aead::{Aead, NewAead, Payload};
pub use aes_siv::{Aes128SivAead, Aes256SivAead};

use aead::generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use std::panic;

pub type Aes128SivNonce = GenericArray<u8, <Aes128SivAead as Aead>::NonceSize>;
pub type Aes256SivNonce = GenericArray<u8, <Aes128SivAead as Aead>::NonceSize>;
pub type Aes128SivKey = GenericArray<u8, <Aes128SivAead as NewAead>::KeySize>;
pub type Aes256SivKey = GenericArray<u8, <Aes256SivAead as NewAead>::KeySize>;

///Error returned by `GenericArrayExt` methods if the slice passed in is the wrong length.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct LengthMismatchError;

///Annoyingly, GenericArray's `from_slice` constructors panic if the slice is the wrong length.
///This extension trait adds methods that catch the panic and return an error result instead.
pub trait GenericArrayExt<T, N>
where
    N: ArrayLength<T>,
{
    fn try_from_slice(slice: &[T]) -> Result<&GenericArray<T, N>, LengthMismatchError>
    where
        T: panic::RefUnwindSafe,
    {
        panic::catch_unwind(move || GenericArray::from_slice(slice))
            .map_err(|_| LengthMismatchError {})
    }

    fn try_clone_from_slice(slice: &[T]) -> Result<GenericArray<T, N>, LengthMismatchError>
    where
        T: panic::RefUnwindSafe + Clone,
    {
        panic::catch_unwind(move || GenericArray::clone_from_slice(slice))
            .map_err(|_| LengthMismatchError {})
    }
}

impl<T, N> GenericArrayExt<T, N> for GenericArray<T, N> where N: ArrayLength<T> {}

pub fn keygen<R: RngCore + CryptoRng>(rand: &mut R) -> Aes128SivKey {
    let mut key = Aes128SivKey::default();
    rand.fill_bytes(key.as_mut_slice());
    key
}

#[cfg(test)]
pub fn keygen_test<R: RngCore>(rand: &mut R) -> Aes128SivKey {
    let mut key = Aes128SivKey::default();
    rand.fill_bytes(key.as_mut_slice());
    key
}
