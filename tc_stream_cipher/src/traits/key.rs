/// Provides borrowed access to cipher key bytes.
///
/// Implement this trait for a custom parameter container, or use one of the
/// supplied ones: [`crate::KeyRef`] and [`crate::KeyFixed`] for key-only
/// ciphers, [`crate::KeyWithIvRef`] and [`crate::KeyWithIvFixed`] with an IV,
/// and `KeyOwned` / `KeyWithIvOwned` with the `alloc` feature. Key-length
/// validation belongs to the receiving engine.
pub trait KeyParams {
    /// Borrows the key bytes for as long as the container is borrowed.
    ///
    /// The returned slice is secret material. Timing is
    /// implementation-defined; the supplied containers return their slice
    /// without inspecting its contents.
    fn key(&self) -> &[u8];
}
