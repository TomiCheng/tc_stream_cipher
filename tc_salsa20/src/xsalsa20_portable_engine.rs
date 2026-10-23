use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

use crate::salsa::{self, State};

/// XSalsa20 (Bernstein, 2008) in portable Rust, as Bouncy Castle's
/// `XSalsa20Engine`: a 32-byte key and a 24-byte IV. HSalsa20 derives a subkey
/// from the key and the first 16 IV bytes, then 20-round Salsa20 runs on the
/// last 8.
///
/// One key and IV give at most 2^70 bytes, as in Bouncy Castle; past that,
/// processing returns `MaxBytesExceeded`.
///
/// **Constant time:** only 32-bit additions, XORs and fixed rotations,
/// branching only on lengths and the keystream position. The state words, the
/// subkey derivation's scratch and the current keystream block are wiped on
/// drop or once used; the caller's key and copies left in registers or on the
/// stack are not.
pub struct Xsalsa20PortableEngine {
    state: State,
}

impl Xsalsa20PortableEngine {
    /// Key length in bytes.
    pub const KEY_BYTES: usize = 32;
    /// IV length in bytes.
    pub const IV_BYTES: usize = 24;

    /// An engine without a key; `init` must come before processing. Constant
    /// time.
    pub const fn new() -> Self {
        Self {
            state: State::new(salsa::DEFAULT_ROUNDS),
        }
    }
}

impl Default for Xsalsa20PortableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Xsalsa20PortableEngine {
    /// Writes `XSalsa20` without inspecting key material. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XSalsa20")
    }
}

impl StreamCipher for Xsalsa20PortableEngine {
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

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Xsalsa20PortableEngine {
    type Error = InitError;

    /// Installs a 32-byte key and a 24-byte IV, derives the subkey and starts the
    /// keystream at block zero. The direction is ignored: both directions apply the
    /// same keystream. A rejected length leaves the previous key, IV and position in
    /// place. Constant time; branches only on the lengths.
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.len() != Self::KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() != Self::IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }

        let words = &mut self.state.words;
        words.zeroize();
        salsa::set_key(words, key, iv);
        words[8] = u32::from_le_bytes([iv[8], iv[9], iv[10], iv[11]]);
        words[9] = u32::from_le_bytes([iv[12], iv[13], iv[14], iv[15]]);

        // HSalsa20: the block output minus its input, taking the diagonal and the
        // middle four words as the subkey
        let mut output = salsa::block(salsa::DEFAULT_ROUNDS, words);
        words[1] = output[0].wrapping_sub(words[0]);
        words[2] = output[5].wrapping_sub(words[5]);
        words[3] = output[10].wrapping_sub(words[10]);
        words[4] = output[15].wrapping_sub(words[15]);
        words[11] = output[6].wrapping_sub(words[6]);
        words[12] = output[7].wrapping_sub(words[7]);
        words[13] = output[8].wrapping_sub(words[8]);
        words[14] = output[9].wrapping_sub(words[9]);
        output.zeroize();

        words[6] = u32::from_le_bytes([iv[16], iv[17], iv[18], iv[19]]);
        words[7] = u32::from_le_bytes([iv[20], iv[21], iv[22], iv[23]]);
        self.state.finish_initialization();
        Ok(())
    }
}
