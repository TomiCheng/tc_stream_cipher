use crate::KeyParams;
use alloc::vec::Vec;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// An owned key vector that is wiped on drop.
///
/// Available with the `alloc` feature. Construction transfers the vector rather
/// than cloning its bytes. The engine validates the key length.
/// Wiping this container does not erase copies held elsewhere.
pub struct KeyOwned {
    key: Vec<u8>,
}

impl KeyOwned {
    /// Takes ownership without allocating or validating the key length.
    /// Constant time: moves vector metadata without inspecting key bytes.
    pub const fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl KeyParams for KeyOwned {
    /// Returns the stored key bytes without copying them.
    /// Constant time: does not inspect key contents.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Zeroize for KeyOwned {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for KeyOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyOwned {}
