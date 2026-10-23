use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

use crate::salsa::{self, State};

/// Whether `rounds` is positive, even and within Bouncy Castle's bound.
pub(crate) const fn valid_rounds(rounds: usize) -> bool {
    rounds != 0 && rounds & 1 == 0 && rounds <= salsa::MAX_ROUNDS
}

/// Salsa20 (Bernstein, 2005) in portable Rust, as Bouncy Castle's
/// `Salsa20Engine`: a 16- or 32-byte key and an 8-byte IV, with an even round
/// count, 20 unless [`with_rounds`](Self::with_rounds) picks another (8 and 12
/// are the reduced-round variants).
///
/// One key and IV give at most 2^70 bytes, as in Bouncy Castle; past that,
/// processing returns `MaxBytesExceeded`.
///
/// **Constant time:** only 32-bit additions, XORs and fixed rotations. The
/// branches depend on lengths, the round count and the keystream position,
/// which are public. The state words and the current keystream block are wiped
/// on drop; the caller's key and copies left in registers or on the stack are
/// not.
pub struct Salsa20PortableEngine {
    rounds: usize,
    state: State,
}

impl Salsa20PortableEngine {
    /// Accepted key lengths in bytes.
    pub const KEY_BYTES: [usize; 2] = [16, 32];
    /// IV length in bytes.
    pub const IV_BYTES: usize = 8;
    /// Default round count.
    pub const DEFAULT_ROUNDS: usize = salsa::DEFAULT_ROUNDS;

    /// A 20-round engine without a key; `init` must come before processing.
    /// Constant time.
    pub const fn new() -> Self {
        Self::build(salsa::DEFAULT_ROUNDS)
    }

    /// An engine with a positive, even round count, or `InvalidRounds`. Constant
    /// time.
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
            state: State::new(rounds),
        }
    }
}

impl Default for Salsa20PortableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Salsa20PortableEngine {
    /// Writes `Salsa20`, or `Salsa20/12` and the like for other round counts, as
    /// Bouncy Castle does, without inspecting key material. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rounds == salsa::DEFAULT_ROUNDS {
            f.write_str("Salsa20")
        } else {
            write!(f, "Salsa20/{}", self.rounds)
        }
    }
}

impl StreamCipher for Salsa20PortableEngine {
    type Error = StreamError;

    /// XORs `input` with the next keystream byte. Returns `NotInitialised` before
    /// `init` and `MaxBytesExceeded` at the limit. Constant time.
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        self.state.return_byte(input)
    }

    /// XORs `input` with the keystream into the start of `output` and returns
    /// `input.len()`. Returns `NotInitialised` before `init`, `BufferTooShort` if
    /// `output` is shorter than `input`, and `MaxBytesExceeded` if `input` would
    /// pass the limit. Constant time; branches only on the lengths and the
    /// position.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        self.state.process_bytes(input, output)
    }

    /// Returns to the start of the keystream for the current key and IV.
    /// Constant time.
    fn reset(&mut self) {
        self.state.reset();
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Salsa20PortableEngine {
    type Error = InitError;

    /// Installs a 16- or 32-byte key and an 8-byte IV, and starts the keystream
    /// at block zero. The direction is ignored: both directions apply the same
    /// keystream. A rejected length leaves the previous key, IV and position in
    /// place. Constant time; branches only on the lengths.
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !Self::KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() != Self::IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }
        self.state.init(key, iv);
        Ok(())
    }
}
