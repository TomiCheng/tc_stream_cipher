//! The portable XChaCha20 engine.

use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

use crate::DEFAULT_ROUNDS;
use crate::chacha::{self, Counter, STATE_WORDS, State};

const KEY_BYTES: usize = 32;

/// XChaCha20 in portable Rust: HChaCha20 derives a subkey from the key and
/// the first 16 nonce bytes, then IETF ChaCha20 runs on the rest. The 192-bit
/// nonce is long enough to choose at random.
///
/// **Constant time:** only 32-bit additions, XORs and fixed rotations. The
/// branches depend on lengths and the keystream position, which are public.
/// The subkey, the key words and the current keystream block are wiped; the
/// caller's key and copies left in registers or on the stack are not.
pub struct XChaCha20PortableEngine {
    state: State,
}

impl XChaCha20PortableEngine {
    /// Key length in bytes (256 bits).
    pub const KEY_BYTES: usize = KEY_BYTES;
    /// IV (nonce) length in bytes.
    pub const IV_BYTES: usize = 24;

    /// An engine without a key; `init` must come before processing.
    /// Constant time.
    pub const fn new() -> Self {
        Self {
            state: State::new(DEFAULT_ROUNDS, Counter::Ietf),
        }
    }
}

impl Default for XChaCha20PortableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for XChaCha20PortableEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the
    /// formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XChaCha20")
    }
}

impl StreamCipher for XChaCha20PortableEngine {
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

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for XChaCha20PortableEngine {
    type Error = InitError;

    /// Installs a 32-byte key and a 24-byte IV, and starts the keystream at
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

        let mut subkey = hchacha20(key, &iv[..16]);
        let mut ietf_iv = [0u8; 12];
        ietf_iv[4..].copy_from_slice(&iv[16..]);
        self.state.init_ietf(&subkey, &ietf_iv);
        subkey.zeroize();
        Ok(())
    }
}

/// HChaCha20: the ChaCha20 permutation over the key and a 16-byte nonce,
/// keeping words 0 to 3 and 12 to 15 as the subkey.
fn hchacha20(key: &[u8], nonce: &[u8]) -> [u8; KEY_BYTES] {
    let mut input = [0u32; STATE_WORDS];
    chacha::set_key(&mut input, key);
    chacha::load_words(nonce, &mut input[12..]);

    let mut words = chacha::permutation(DEFAULT_ROUNDS, &input);
    let mut subkey = [0u8; KEY_BYTES];
    chacha::store_words(&words[..4], &mut subkey[..16]);
    chacha::store_words(&words[12..], &mut subkey[16..]);
    input.zeroize();
    words.zeroize();
    subkey
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hchacha20_matches_the_xchacha_draft_vector() {
        let key: [u8; KEY_BYTES] = core::array::from_fn(|index| index as u8);
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41,
            0x59, 0x27,
        ];
        assert_eq!(
            hchacha20(&key, &nonce),
            [
                0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
                0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
                0x26, 0xd3, 0xec, 0xdc,
            ]
        );
    }
}
