use crate::{IvParams, KeyParams};

/// A borrowed key and IV (nonce) with no allocation or copying.
///
/// The caller owns the bytes and is responsible for wiping the key. Dropping
/// this view does not modify either slice. The engine validates both lengths.
pub struct KeyWithIvRef<'a> {
    key: &'a [u8],
    iv: &'a [u8],
}

impl<'a> KeyWithIvRef<'a> {
    /// Borrows the key and IV without validating their lengths.
    /// Constant time: does not inspect the bytes.
    pub const fn new(key: &'a [u8], iv: &'a [u8]) -> Self {
        Self { key, iv }
    }
}

impl KeyParams for KeyWithIvRef<'_> {
    /// Returns the stored key bytes without copying them.
    /// Constant time: does not inspect key contents.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for KeyWithIvRef<'_> {
    /// Returns the stored IV bytes without copying them.
    /// Constant time: does not inspect the IV.
    fn iv(&self) -> &[u8] {
        self.iv
    }
}
