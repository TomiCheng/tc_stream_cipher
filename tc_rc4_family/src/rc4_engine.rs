use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

#[cfg(not(feature = "rustcrypto"))]
use crate::Rc4PortableEngine as Inner;
#[cfg(feature = "rustcrypto")]
use crate::Rc4RustCryptoEngine as Inner;

/// RC4 (Rivest, 1987), as Bouncy Castle's `RC4Engine`: a key of 1 to 256
/// bytes and no IV. It runs on RustCrypto's `rc4` with the `rustcrypto` feature
/// and on [`Rc4PortableEngine`](crate::Rc4PortableEngine) without it; both
/// accept the same keys, and the backend is chosen at compile time.
///
/// RustCrypto's key schedule is faster, but its keystream measured slower than
/// the portable engine's at every length benchmarked (see `BENCHES.md`), so
/// enabling `rustcrypto` slows bulk RC4 down; it is there for those who prefer
/// RustCrypto's implementation.
///
/// **Variable time (cache timing):** both backends swap and output
/// permutation entries at indices taken from the permutation, so the positions
/// depend on secrets. RC4's keystream has known biases and the cipher is
/// broken; it is kept for compatibility only. The permutation and the key are
/// wiped on drop.
pub struct Rc4Engine {
    inner: Inner,
}

impl Rc4Engine {
    /// Shortest accepted key length in bytes.
    pub const MIN_KEY_BYTES: usize = 1;
    /// Longest accepted key length in bytes.
    pub const MAX_KEY_BYTES: usize = 256;

    /// An engine without a key; `init` must come before processing. Constant
    /// time.
    pub const fn new() -> Self {
        Self {
            inner: Inner::new(),
        }
    }
}

impl Default for Rc4Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc4Engine {
    /// Writes `RC4` without inspecting key material. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl StreamCipher for Rc4Engine {
    type Error = StreamError;

    /// XORs `input` with the next keystream byte. Returns `NotInitialised`
    /// before `init`. Variable time (table lookups).
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        self.inner.return_byte(input)
    }

    /// XORs `input` with the keystream into the start of `output` and returns
    /// `input.len()`; errors leave `output` and the position unchanged. Variable
    /// time (table lookups).
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        self.inner.process_bytes(input, output)
    }

    /// Returns to the start of the keystream for the current key. Variable time
    /// (the permutation is rebuilt).
    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl<P: KeyParams + ?Sized> StreamCipherInit<P> for Rc4Engine {
    type Error = InitError;

    /// Installs a key of 1 to 256 bytes. The direction is ignored. A rejected
    /// length leaves the previous key and position in place. Variable time (the key
    /// schedule indexes the permutation with the key and the state).
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.inner.init(direction, params)
    }
}
