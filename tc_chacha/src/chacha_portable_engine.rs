//! The portable original ChaCha engine.

use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

use crate::DEFAULT_ROUNDS;
use crate::chacha::{Counter, State};

/// Bouncy Castle's upper bound on the round count.
const MAX_ROUNDS: usize = i32::MAX as usize - 1;

/// Whether `rounds` is positive, even and within Bouncy Castle's bound.
pub(crate) const fn valid_rounds(rounds: usize) -> bool {
    rounds != 0 && rounds & 1 == 0 && rounds <= MAX_ROUNDS
}

/// The original ChaCha (Bernstein, 2008) in portable Rust: a 64-bit nonce
/// and a 64-bit block counter, with a 16- or 32-byte key and an even round
/// count, 20 unless [`with_rounds`](Self::with_rounds) picks another (8 and
/// 12 are the reduced-round variants).
///
/// One key and IV give just under 2^69 bytes, Bouncy Castle's limit; past
/// that, processing returns `MaxBytesExceeded`.
///
/// **Constant time:** only 32-bit additions, XORs and fixed rotations. The
/// branches depend on lengths, the round count and the keystream position,
/// which are public. The key words and the current keystream block are wiped
/// on drop; the caller's key and copies left in registers or on the stack are
/// not.
pub struct ChaChaPortableEngine {
    rounds: usize,
    state: State,
}

impl ChaChaPortableEngine {
    /// Accepted key lengths in bytes.
    pub const KEY_BYTES: [usize; 2] = [16, 32];
    /// IV (nonce) length in bytes.
    pub const IV_BYTES: usize = 8;

    /// A 20-round engine without a key; `init` must come before processing.
    /// Constant time.
    pub const fn new() -> Self {
        Self::build(DEFAULT_ROUNDS)
    }

    /// An engine with a positive, even round count, or `InvalidRounds`.
    /// Constant time.
    pub const fn with_rounds(rounds: usize) -> Result<Self, InitError> {
        if !valid_rounds(rounds) {
            return Err(InitError::InvalidRounds(rounds));
        }
        Ok(Self::build(rounds))
    }

    /// `rounds` must satisfy [`valid_rounds`].
    pub(crate) const fn build(rounds: usize) -> Self {
        Self {
            rounds,
            state: State::new(rounds, Counter::Original),
        }
    }
}

impl Default for ChaChaPortableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ChaChaPortableEngine {
    /// Writes `ChaCha` and the round count without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the
    /// formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChaCha{}", self.rounds)
    }
}

impl StreamCipher for ChaChaPortableEngine {
    type Error = StreamError;

    /// XORs `input` with the next keystream byte. Returns `NotInitialised`
    /// before `init`, and `MaxBytesExceeded` at the byte limit. Constant time.
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        self.state.return_byte(input)
    }

    /// XORs `input` with the keystream into the start of `output` and returns
    /// `input.len()`; any longer tail of `output` is left untouched. Returns
    /// `NotInitialised` before `init`, `BufferTooShort` if `output` is shorter
    /// than `input`, and `MaxBytesExceeded` if `input` would pass the byte
    /// limit. Errors leave `output` and the position unchanged. Constant time;
    /// branches only on the lengths and the position.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        self.state.process_bytes(input, output)
    }

    /// Returns to the start of the keystream for the current key and IV.
    /// Constant time.
    fn reset(&mut self) {
        self.state.reset();
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for ChaChaPortableEngine {
    type Error = InitError;

    /// Installs a 16- or 32-byte key and an 8-byte IV, and starts the
    /// keystream at block zero. The direction is ignored: both directions
    /// apply the same keystream. A rejected length leaves the previous key, IV
    /// and position in place. Constant time; branches only on the lengths.
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !Self::KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() != Self::IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }
        self.state.init_original(key, iv);
        Ok(())
    }
}
