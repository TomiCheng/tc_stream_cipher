/// Provides borrowed access to initialization-vector (nonce) bytes.
///
/// Separate from [`crate::KeyParams`] because some stream ciphers, such as
/// RC4, take no IV. Implement both for a custom container, or use
/// [`crate::KeyWithIvRef`], [`crate::KeyWithIvFixed`] or, with the `alloc`
/// feature, `KeyWithIvOwned`. IV-length validation belongs to the receiving
/// engine.
pub trait IvParams {
    /// Borrows the IV bytes for as long as the container is borrowed.
    ///
    /// Timing is implementation-defined; the supplied containers return their
    /// slice without inspecting its contents.
    fn iv(&self) -> &[u8];
}
