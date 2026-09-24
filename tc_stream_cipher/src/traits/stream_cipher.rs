//! Stream-cipher contracts.

use crate::CipherDirection;

/// An initialized symmetric-key stream cipher.
///
/// This trait contains only operations that can be dispatched through a trait
/// object. Initialization is provided independently by [`StreamCipherInit`].
///
/// Implementations with the same [`Error`](StreamCipher::Error) type can be
/// stored together behind `dyn StreamCipher<Error = E>` after initialization.
pub trait StreamCipher {
    /// The failure type returned by stream processing; initialization reports
    /// through [`StreamCipherInit::Error`].
    type Error: core::error::Error;

    /// Encrypts or decrypts one byte and advances the keystream.
    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error>;

    /// Processes `input` into `output` and returns the number of bytes written.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Restores the state established by the most recent initialization.
    fn reset(&mut self);
}

/// Initializes an object from parameters of type `P`.
///
/// This trait is independent from [`StreamCipher`]. Consumers that need both
/// capabilities use `C: StreamCipher + StreamCipherInit<P>`. Keeping `P` as a
/// trait parameter lets one caller-owned parameter object flow through any
/// number of composing cipher layers.
pub trait StreamCipherInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the cipher with the supplied parameters.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}
