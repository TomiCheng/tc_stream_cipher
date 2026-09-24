//! The three ChaCha variants through the RustCrypto `chacha20` crate.

use core::fmt;

use chacha20::cipher::{KeyIvInit, StreamCipher as _, StreamCipherSeek as _};
use chacha20::{ChaCha20, ChaCha20Legacy, XChaCha20};
use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

/// Defines one engine over a RustCrypto cipher type; the variants differ only
/// in that type, the IV length and the name.
macro_rules! rustcrypto_engine {
    (
        $(#[$meta:meta])*
        $name:ident($cipher:ty), iv_bytes: $iv_bytes:literal, algo_name: $algo_name:literal
    ) => {
        $(#[$meta])*
        pub struct $name {
            cipher: Option<$cipher>,
        }

        impl $name {
            /// Key length in bytes (256 bits).
            pub const KEY_BYTES: usize = 32;
            /// IV (nonce) length in bytes.
            pub const IV_BYTES: usize = $iv_bytes;

            /// An engine without a key; `init` must come before processing.
            /// Constant time.
            pub const fn new() -> Self {
                Self { cipher: None }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            /// Writes the algorithm name without inspecting key material.
            /// Constant time with respect to the key; output timing depends on
            /// the formatter.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($algo_name)
            }
        }

        impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for $name {
            type Error = InitError;

            /// Installs a 32-byte key and an IV of
            /// [`IV_BYTES`](Self::IV_BYTES) bytes, and starts the keystream at
            /// block zero. The direction is ignored: both directions apply the
            /// same keystream. A rejected length leaves the previous key, IV
            /// and position in place. Constant time; branches only on the
            /// lengths.
            fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
                let key = params.key();
                let iv = params.iv();
                if key.len() != Self::KEY_BYTES {
                    return Err(InitError::InvalidKeyLength(key.len()));
                }
                if iv.len() != Self::IV_BYTES {
                    return Err(InitError::InvalidIvLength(iv.len()));
                }
                // Both lengths were checked above, so this cannot fail.
                let cipher = <$cipher>::new_from_slices(key, iv)
                    .map_err(|_| InitError::InvalidKeyLength(key.len()))?;
                self.cipher = Some(cipher);
                Ok(())
            }
        }

        impl StreamCipher for $name {
            type Error = StreamError;

            /// XORs `input` with the next keystream byte. Returns
            /// `NotInitialised` before `init`, and `CounterExhausted` once the
            /// keystream for this key and IV is used up. Constant time.
            fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
                let cipher = self.cipher.as_mut().ok_or(StreamError::NotInitialised)?;
                let mut byte = [input];
                cipher
                    .try_apply_keystream(&mut byte)
                    .map_err(|_| StreamError::CounterExhausted)?;
                Ok(byte[0])
            }

            /// XORs `input` with the keystream into the start of `output` and
            /// returns `input.len()`; any longer tail of `output` is left
            /// untouched. Returns `NotInitialised` before `init`,
            /// `BufferTooShort` if `output` is shorter than `input`, and
            /// `CounterExhausted` if `input` would run past the end of the
            /// keystream. Errors leave `output` and the position unchanged.
            /// Constant time; branches only on the lengths.
            fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
                let cipher = self.cipher.as_mut().ok_or(StreamError::NotInitialised)?;
                let output = output
                    .get_mut(..input.len())
                    .ok_or(StreamError::BufferTooShort)?;
                cipher
                    .try_apply_keystream_b2b(input, output)
                    .map_err(|_| StreamError::CounterExhausted)?;
                Ok(input.len())
            }

            /// Returns to the start of the keystream for the current key and
            /// IV; does nothing before `init`. Constant time.
            fn reset(&mut self) {
                if let Some(cipher) = &mut self.cipher {
                    cipher.seek(0u64);
                }
            }
        }
    };
}

rustcrypto_engine! {
    /// The original ChaCha20 (Bernstein, 2008): a 64-bit nonce and a 64-bit
    /// block counter, through RustCrypto's `ChaCha20Legacy`.
    ///
    /// Only 32-byte keys and 20 rounds: RustCrypto has neither the 16-byte key
    /// nor the reduced-round forms of the original layout.
    ///
    /// **Constant time:** ChaCha uses only 32-bit additions, XORs and fixed
    /// rotations on every RustCrypto backend. The backend is chosen from the
    /// processor's features, which are public. The keystream state and its
    /// buffered bytes are wiped on drop; the caller's key and copies left in
    /// registers or on the stack are not.
    ChaChaRustCryptoEngine(ChaCha20Legacy), iv_bytes: 8, algo_name: "ChaCha20"
}

rustcrypto_engine! {
    /// IETF ChaCha20 (RFC 8439): a 96-bit nonce and a 32-bit block counter,
    /// through RustCrypto's `ChaCha20`.
    ///
    /// One key and nonce give at most 2^32 blocks (256 GiB); past that,
    /// processing returns `CounterExhausted`. The keystream starts at block
    /// zero, whereas RFC 8439's encryption examples start at block one.
    ///
    /// **Constant time:** ChaCha uses only 32-bit additions, XORs and fixed
    /// rotations on every RustCrypto backend. The backend is chosen from the
    /// processor's features, which are public. The keystream state and its
    /// buffered bytes are wiped on drop; the caller's key and copies left in
    /// registers or on the stack are not.
    ChaCha7539RustCryptoEngine(ChaCha20), iv_bytes: 12, algo_name: "ChaCha7539"
}

rustcrypto_engine! {
    /// XChaCha20: HChaCha20 derives a subkey from the key and the first 16
    /// nonce bytes, then IETF ChaCha20 runs on the rest, through RustCrypto's
    /// `XChaCha20`. The 192-bit nonce is long enough to choose at random.
    ///
    /// **Constant time:** ChaCha uses only 32-bit additions, XORs and fixed
    /// rotations on every RustCrypto backend. The backend is chosen from the
    /// processor's features, which are public. The keystream state and its
    /// buffered bytes are wiped on drop; the caller's key and copies left in
    /// registers or on the stack are not.
    XChaCha20RustCryptoEngine(XChaCha20), iv_bytes: 24, algo_name: "XChaCha20"
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_wrapped_rustcrypto_ciphers_wipe_their_state_and_buffered_keystream_on_drop() {
        fn wiped_on_drop<T: cipher::zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<chacha20::ChaCha20Legacy>();
        wiped_on_drop::<chacha20::ChaCha20>();
        wiped_on_drop::<chacha20::XChaCha20>();
    }
}
