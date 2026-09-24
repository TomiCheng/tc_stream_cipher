use crate::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// An owned, fixed-size key array that is wiped on drop.
///
/// No allocator is required. The engine validates whether the size is suitable.
/// Storing an array here does not erase other copies, including the caller's
/// original array.
pub struct KeyFixed<const N: usize> {
    key: [u8; N],
}

impl<const N: usize> KeyFixed<N> {
    /// Stores the supplied array without validating its size.
    /// Constant time with respect to key contents; copying cost depends on `N`.
    pub const fn new(key: [u8; N]) -> Self {
        Self { key }
    }
}

impl<const N: usize> KeyParams for KeyFixed<N> {
    /// Returns the stored key bytes without copying them.
    /// Constant time: does not inspect key contents.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl<const N: usize> Zeroize for KeyFixed<N> {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<const N: usize> Drop for KeyFixed<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for KeyFixed<N> {}
