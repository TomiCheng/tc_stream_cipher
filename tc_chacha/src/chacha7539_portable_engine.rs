//! The portable IETF ChaCha20 engine.

use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

use crate::DEFAULT_ROUNDS;
use crate::chacha::{Counter, State};

/// IETF ChaCha20 (RFC 8439) in portable Rust: a 96-bit nonce and a 32-bit
/// block counter.
///
/// One key and nonce give at most 2^32 blocks (256 GiB); past that,
/// processing returns `CounterExhausted`. The keystream starts at block zero,
/// whereas RFC 8439's encryption examples start at block one.
///
/// **Constant time:** only 32-bit additions, XORs and fixed rotations. The
/// branches depend on lengths and the keystream position, which are public.
/// The key words and the current keystream block are wiped on drop; the
/// caller's key and copies left in registers or on the stack are not.
pub struct ChaCha7539PortableEngine {
    state: State,
}

impl ChaCha7539PortableEngine {
    /// Key length in bytes (256 bits).
    pub const KEY_BYTES: usize = 32;
    /// IV (nonce) length in bytes.
    pub const IV_BYTES: usize = 12;

    /// An engine without a key; `init` must come before processing.
    /// Constant time.
    pub const fn new() -> Self {
        Self {
            state: State::new(DEFAULT_ROUNDS, Counter::Ietf),
        }
    }
}

impl Default for ChaCha7539PortableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ChaCha7539PortableEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the
    /// formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChaCha7539")
    }
}

impl StreamCipher for ChaCha7539PortableEngine {
    type Error = StreamError;

    /// XORs `input` with the next keystream byte. Returns `NotInitialised`
    /// before `init`, and `CounterExhausted` once the counter is used up.
    /// Constant time.
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        self.state.return_byte(input)
    }

    /// XORs `input` with the keystream into the start of `output` and returns
    /// `input.len()`; any longer tail of `output` is left untouched. Returns
    /// `NotInitialised` before `init`, `BufferTooShort` if `output` is shorter
    /// than `input`, and `CounterExhausted` if `input` would run past the
    /// counter. Errors leave `output` and the position unchanged. Constant
    /// time; branches only on the lengths and the position.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        self.state.process_bytes(input, output)
    }

    /// Returns to the start of the keystream for the current key and IV.
    /// Constant time.
    fn reset(&mut self) {
        self.state.reset();
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for ChaCha7539PortableEngine {
    type Error = InitError;

    /// Installs a 32-byte key and a 12-byte IV, and starts the keystream at
    /// block zero. The direction is ignored: both directions apply the same
    /// keystream. A rejected length leaves the previous key, IV and position
    /// in place. Constant time; branches only on the lengths.
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.len() != Self::KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() != Self::IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }
        self.state.init_ietf(key, iv);
        Ok(())
    }
}
