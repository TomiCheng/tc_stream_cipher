use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

#[cfg(not(feature = "rustcrypto"))]
use crate::Xsalsa20PortableEngine as Inner;
#[cfg(feature = "rustcrypto")]
use crate::Xsalsa20RustCryptoEngine as Inner;

/// XSalsa20 (Bernstein, 2008), as Bouncy Castle's `XSalsa20Engine`: a 32-byte
/// key and a 24-byte IV, on RustCrypto's `XSalsa20` with the `rustcrypto`
/// feature and on [`Xsalsa20PortableEngine`](crate::Xsalsa20PortableEngine)
/// without it. Both accept the same keys and IVs, and the backend is chosen at
/// compile time.
///
/// **Constant time:** both backends use only 32-bit additions, XORs and fixed
/// rotations. Keystream state is wiped on drop; the caller's key and copies
/// left in registers or on the stack are not.
pub struct Xsalsa20Engine {
    inner: Inner,
}

impl Xsalsa20Engine {
    /// Key length in bytes.
    pub const KEY_BYTES: usize = 32;
    /// IV length in bytes.
    pub const IV_BYTES: usize = 24;

    /// An engine without a key; `init` must come before processing. Constant
    /// time.
    pub const fn new() -> Self {
        Self {
            inner: Inner::new(),
        }
    }
}

impl Default for Xsalsa20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Xsalsa20Engine {
    /// Writes `XSalsa20` without inspecting key material. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl StreamCipher for Xsalsa20Engine {
    type Error = StreamError;

    /// XORs `input` with the next keystream byte; see the backend for the
    /// errors. Constant time.
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        self.inner.return_byte(input)
    }

    /// XORs `input` with the keystream into the start of `output` and returns
    /// `input.len()`; errors leave `output` and the position unchanged. Constant
    /// time; branches only on the lengths and the position.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        self.inner.process_bytes(input, output)
    }

    /// Returns to the start of the keystream for the current key and IV.
    /// Constant time.
    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Xsalsa20Engine {
    type Error = InitError;

    /// Installs a 32-byte key and a 24-byte IV and starts the keystream at block
    /// zero. The direction is ignored. A rejected length leaves the previous key,
    /// IV and position in place. Constant time; branches only on the lengths.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.inner.init(direction, params)
    }
}
