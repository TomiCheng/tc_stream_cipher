use crate::{IvParams, KeyParams};
use alloc::vec::Vec;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// An owned key vector and IV (nonce) vector, both wiped on drop.
///
/// Available with the `alloc` feature. Construction transfers the vectors
/// rather than cloning their bytes. The engine validates both lengths.
/// Wiping this container does not erase copies held elsewhere. The IV is not
/// secret, but is wiped with the key to keep one rule.
pub struct KeyWithIvOwned {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl KeyWithIvOwned {
    /// Takes ownership without allocating or validating the lengths.
    /// Constant time: moves vector metadata without inspecting the bytes.
    pub const fn new(key: Vec<u8>, iv: Vec<u8>) -> Self {
        Self { key, iv }
    }
}

impl KeyParams for KeyWithIvOwned {
    /// Returns the stored key bytes without copying them.
    /// Constant time: does not inspect key contents.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl IvParams for KeyWithIvOwned {
    /// Returns the stored IV bytes without copying them.
    /// Constant time: does not inspect the IV.
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl Zeroize for KeyWithIvOwned {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Drop for KeyWithIvOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyWithIvOwned {}
