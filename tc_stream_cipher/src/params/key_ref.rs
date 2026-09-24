use crate::KeyParams;

/// A borrowed key slice with no allocation or copying.
///
/// The caller owns the bytes and is responsible for wiping them. Dropping this
/// view does not modify the key. The engine validates the key length.
pub struct KeyRef<'a> {
    key: &'a [u8],
}

impl<'a> KeyRef<'a> {
    /// Borrows key bytes without validating their length.
    /// Constant time: does not inspect the bytes.
    pub const fn new(key: &'a [u8]) -> Self {
        Self { key }
    }
}

impl KeyParams for KeyRef<'_> {
    /// Returns the stored key bytes without copying them.
    /// Constant time: does not inspect key contents.
    fn key(&self) -> &[u8] {
        self.key
    }
}
