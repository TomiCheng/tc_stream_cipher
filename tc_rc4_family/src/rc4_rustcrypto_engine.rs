use core::fmt;

use rc4::{KeyInit, Rc4, StreamCipher as _};
use tc_stream_cipher::{
    CipherDirection, InitError, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

const MAX_KEY_BYTES: usize = 256;

/// RC4 through RustCrypto's `rc4::Rc4`: a key of 1 to 256 bytes and no IV.
///
/// `rc4::Rc4` can neither seek nor be cloned, so `reset` reruns the key
/// schedule from a kept copy of the key. The kept key and RustCrypto's
/// permutation are wiped on drop.
///
/// **Variable time (cache timing):** like
/// [`Rc4PortableEngine`](crate::Rc4PortableEngine), it swaps and outputs
/// permutation entries at indices taken from the permutation, so the positions
/// depend on secrets; kept for compatibility only.
pub struct Rc4RustCryptoEngine {
    cipher: Option<Rc4>,
    key: [u8; MAX_KEY_BYTES],
    key_len: usize,
}

impl Rc4RustCryptoEngine {
    /// Shortest accepted key length in bytes.
    pub const MIN_KEY_BYTES: usize = 1;
    /// Longest accepted key length in bytes.
    pub const MAX_KEY_BYTES: usize = MAX_KEY_BYTES;

    /// An engine without a key; `init` must come before processing. Constant
    /// time.
    pub const fn new() -> Self {
        Self {
            cipher: None,
            key: [0; MAX_KEY_BYTES],
            key_len: 0,
        }
    }
}

impl Default for Rc4RustCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc4RustCryptoEngine {
    /// Writes `RC4` without inspecting key material. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RC4")
    }
}

impl StreamCipher for Rc4RustCryptoEngine {
    type Error = StreamError;

    /// XORs `input` with the next keystream byte. Returns `NotInitialised`
    /// before `init`. Variable time (table lookups).
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        let cipher = self.cipher.as_mut().ok_or(StreamError::NotInitialised)?;
        let mut byte = [input];
        cipher.apply_keystream(&mut byte);
        Ok(byte[0])
    }

    /// XORs `input` with the keystream into the start of `output` and returns
    /// `input.len()`. Returns `NotInitialised` before `init` and `BufferTooShort`
    /// if `output` is shorter than `input`; neither moves the position. Variable
    /// time (table lookups).
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        let cipher = self.cipher.as_mut().ok_or(StreamError::NotInitialised)?;
        let output = output
            .get_mut(..input.len())
            .ok_or(StreamError::BufferTooShort)?;
        cipher.apply_keystream_b2b(input, output);
        Ok(input.len())
    }

    /// Reruns the key schedule from the kept key, returning to the start of the
    /// keystream; does nothing before `init`. Variable time (the permutation is
    /// rebuilt).
    fn reset(&mut self) {
        if self.cipher.is_some() {
            // `init` checked the length, so this cannot fail
            self.cipher = Rc4::new_from_slice(&self.key[..self.key_len]).ok();
        }
    }
}

impl<P: KeyParams + ?Sized> StreamCipherInit<P> for Rc4RustCryptoEngine {
    type Error = InitError;

    /// Installs a key of 1 to 256 bytes. The direction is ignored. A rejected
    /// length leaves the previous key and position in place. Variable time (the key
    /// schedule indexes the permutation with the key and the state).
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let cipher =
            Rc4::new_from_slice(key).map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        self.key.zeroize();
        self.key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.cipher = Some(cipher);
        Ok(())
    }
}

impl Drop for Rc4RustCryptoEngine {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_wrapped_rustcrypto_cipher_wipes_its_state_on_drop() {
        fn wiped_on_drop<T: rc4::cipher::zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<rc4::Rc4>();
    }
}
