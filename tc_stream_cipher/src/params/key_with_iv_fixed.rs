use crate::{IvParams, KeyParams};
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// An owned, fixed-size key and IV (nonce), both wiped on drop.
///
/// No allocator is required. The engine validates whether the sizes are
/// suitable; for IETF ChaCha20 this is `KeyWithIvFixed<32, 12>`. Storing the
/// arrays here does not erase other copies, including the caller's originals.
/// The IV is not secret, but is wiped with the key to keep one rule.
pub struct KeyWithIvFixed<const K: usize, const I: usize> {
    key: [u8; K],
    iv: [u8; I],
}

impl<const K: usize, const I: usize> KeyWithIvFixed<K, I> {
    /// Stores the supplied arrays without validating their sizes.
    /// Constant time with respect to their contents; copying cost depends on
    /// `K` and `I`.
    pub const fn new(key: [u8; K], iv: [u8; I]) -> Self {
        Self { key, iv }
    }
}

impl<const K: usize, const I: usize> KeyParams for KeyWithIvFixed<K, I> {
    /// Returns the stored key bytes without copying them.
    /// Constant time: does not inspect key contents.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl<const K: usize, const I: usize> IvParams for KeyWithIvFixed<K, I> {
    /// Returns the stored IV bytes without copying them.
    /// Constant time: does not inspect the IV.
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl<const K: usize, const I: usize> Zeroize for KeyWithIvFixed<K, I> {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl<const K: usize, const I: usize> Drop for KeyWithIvFixed<K, I> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const K: usize, const I: usize> ZeroizeOnDrop for KeyWithIvFixed<K, I> {}
