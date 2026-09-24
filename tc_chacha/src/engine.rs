//! Engines that pick their backend: RustCrypto with the `rustcrypto`
//! feature where it covers the request, the portable engine otherwise.

use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

use crate::DEFAULT_ROUNDS;
use crate::chacha_portable_engine::valid_rounds;
use crate::{ChaCha7539PortableEngine, ChaChaPortableEngine, XChaCha20PortableEngine};
#[cfg(feature = "rustcrypto")]
use crate::{ChaCha7539RustCryptoEngine, ChaChaRustCryptoEngine, XChaCha20RustCryptoEngine};

/// The engine running the original ChaCha for the current key.
enum ChaChaBackend {
    #[cfg(feature = "rustcrypto")]
    RustCrypto(ChaChaRustCryptoEngine),
    Portable(ChaChaPortableEngine),
}

/// The original ChaCha (Bernstein, 2008): a 64-bit nonce and a 64-bit block
/// counter, with a 16- or 32-byte key and an even round count, 20 unless
/// [`with_rounds`](Self::with_rounds) picks another.
///
/// With the `rustcrypto` feature, a 32-byte key at 20 rounds runs on
/// RustCrypto's `ChaCha20Legacy`. RustCrypto has no 16-byte key and no other
/// round count, so those stay on [`ChaChaPortableEngine`]: turning the
/// feature on never changes which keys and round counts work. The only
/// difference is the per-IV limit, just under 2^69 bytes on the portable
/// engine and 2^70 on RustCrypto; neither is reachable in practice.
///
/// **Constant time:** both backends use only 32-bit additions, XORs and
/// fixed rotations. The backend is chosen from the key length and the round
/// count, which are public. Keystream state is wiped on drop; the caller's
/// key and copies left in registers or on the stack are not.
pub struct ChaChaEngine {
    rounds: usize,
    backend: ChaChaBackend,
}

impl ChaChaEngine {
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

    const fn build(rounds: usize) -> Self {
        Self {
            rounds,
            backend: ChaChaBackend::Portable(ChaChaPortableEngine::build(rounds)),
        }
    }

    /// A fresh backend for a key of `key_bytes` bytes.
    #[cfg(feature = "rustcrypto")]
    fn backend_for(&self, key_bytes: usize) -> ChaChaBackend {
        if self.rounds == DEFAULT_ROUNDS && key_bytes == ChaChaRustCryptoEngine::KEY_BYTES {
            ChaChaBackend::RustCrypto(ChaChaRustCryptoEngine::new())
        } else {
            ChaChaBackend::Portable(ChaChaPortableEngine::build(self.rounds))
        }
    }

    /// A fresh backend for a key of `key_bytes` bytes.
    #[cfg(not(feature = "rustcrypto"))]
    fn backend_for(&self, _key_bytes: usize) -> ChaChaBackend {
        ChaChaBackend::Portable(ChaChaPortableEngine::build(self.rounds))
    }
}

impl Default for ChaChaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ChaChaEngine {
    /// Writes `ChaCha` and the round count without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the
    /// formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChaCha{}", self.rounds)
    }
}

impl StreamCipher for ChaChaEngine {
    type Error = StreamError;

    /// XORs `input` with the next keystream byte; see the backend for the
    /// errors. Constant time.
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        match &mut self.backend {
            #[cfg(feature = "rustcrypto")]
            ChaChaBackend::RustCrypto(engine) => engine.return_byte(input),
            ChaChaBackend::Portable(engine) => engine.return_byte(input),
        }
    }

    /// XORs `input` with the keystream into the start of `output` and returns
    /// `input.len()`; errors leave `output` and the position unchanged.
    /// Constant time; branches only on the lengths and the position.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        match &mut self.backend {
            #[cfg(feature = "rustcrypto")]
            ChaChaBackend::RustCrypto(engine) => engine.process_bytes(input, output),
            ChaChaBackend::Portable(engine) => engine.process_bytes(input, output),
        }
    }

    /// Returns to the start of the keystream for the current key and IV.
    /// Constant time.
    fn reset(&mut self) {
        match &mut self.backend {
            #[cfg(feature = "rustcrypto")]
            ChaChaBackend::RustCrypto(engine) => engine.reset(),
            ChaChaBackend::Portable(engine) => engine.reset(),
        }
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for ChaChaEngine {
    type Error = InitError;

    /// Installs a 16- or 32-byte key and an 8-byte IV on the backend that
    /// covers them, and starts the keystream at block zero. The direction is
    /// ignored. A rejected length leaves the previous backend, key, IV and
    /// position in place. Constant time; branches only on the lengths and the
    /// round count.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let mut backend = self.backend_for(params.key().len());
        match &mut backend {
            #[cfg(feature = "rustcrypto")]
            ChaChaBackend::RustCrypto(engine) => engine.init(direction, params)?,
            ChaChaBackend::Portable(engine) => engine.init(direction, params)?,
        }
        self.backend = backend;
        Ok(())
    }
}

/// Defines an engine that forwards to one backend, fixed at compile time.
macro_rules! forwarding_engine {
    (
        $(#[$meta:meta])*
        $name:ident(portable: $portable:ty, rustcrypto: $rustcrypto:ty)
    ) => {
        $(#[$meta])*
        pub struct $name {
            #[cfg(feature = "rustcrypto")]
            inner: $rustcrypto,
            #[cfg(not(feature = "rustcrypto"))]
            inner: $portable,
        }

        impl $name {
            /// Key length in bytes (256 bits).
            pub const KEY_BYTES: usize = <$portable>::KEY_BYTES;
            /// IV (nonce) length in bytes.
            pub const IV_BYTES: usize = <$portable>::IV_BYTES;

            /// An engine without a key; `init` must come before processing.
            /// Constant time: the backend is chosen at compile time.
            pub const fn new() -> Self {
                Self {
                    #[cfg(feature = "rustcrypto")]
                    inner: <$rustcrypto>::new(),
                    #[cfg(not(feature = "rustcrypto"))]
                    inner: <$portable>::new(),
                }
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
                self.inner.fmt(f)
            }
        }

        impl StreamCipher for $name {
            type Error = StreamError;

            /// XORs `input` with the next keystream byte; see the backend for
            /// the errors. Constant time.
            fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
                self.inner.return_byte(input)
            }

            /// XORs `input` with the keystream into the start of `output` and
            /// returns `input.len()`; errors leave `output` and the position
            /// unchanged. Constant time; branches only on the lengths and the
            /// position.
            fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
                self.inner.process_bytes(input, output)
            }

            /// Returns to the start of the keystream for the current key and
            /// IV. Constant time.
            fn reset(&mut self) {
                self.inner.reset();
            }
        }

        impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for $name {
            type Error = InitError;

            /// Installs a 32-byte key and an IV of
            /// [`IV_BYTES`](Self::IV_BYTES) bytes, and starts the keystream at
            /// block zero. The direction is ignored. A rejected length leaves
            /// the previous key, IV and position in place. Constant time;
            /// branches only on the lengths.
            fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
                self.inner.init(direction, params)
            }
        }
    };
}

forwarding_engine! {
    /// IETF ChaCha20 (RFC 8439): a 96-bit nonce and a 32-bit block counter,
    /// on RustCrypto's `ChaCha20` with the `rustcrypto` feature and on
    /// [`ChaCha7539PortableEngine`] without it. Both accept the same keys and
    /// IVs and stop after 2^32 blocks (256 GiB) with `CounterExhausted`.
    ///
    /// **Constant time:** both backends use only 32-bit additions, XORs and
    /// fixed rotations. Keystream state is wiped on drop; the caller's key and
    /// copies left in registers or on the stack are not.
    ChaCha7539Engine(portable: ChaCha7539PortableEngine, rustcrypto: ChaCha7539RustCryptoEngine)
}

forwarding_engine! {
    /// XChaCha20: a 192-bit nonce, long enough to choose at random, on
    /// RustCrypto's `XChaCha20` with the `rustcrypto` feature and on
    /// [`XChaCha20PortableEngine`] without it. Both accept the same keys and
    /// IVs.
    ///
    /// **Constant time:** both backends use only 32-bit additions, XORs and
    /// fixed rotations. Keystream state is wiped on drop; the caller's key and
    /// copies left in registers or on the stack are not.
    XChaCha20Engine(portable: XChaCha20PortableEngine, rustcrypto: XChaCha20RustCryptoEngine)
}

#[cfg(test)]
mod tests {
    use tc_stream_cipher::{CipherDirection, KeyWithIvRef, StreamCipherInit};

    use super::{ChaChaBackend, ChaChaEngine};

    /// Whether `engine` ran on RustCrypto after keying it with `key_bytes`.
    fn on_rustcrypto(mut engine: ChaChaEngine, key_bytes: usize) -> bool {
        let params = KeyWithIvRef::new(&[0; 32][..key_bytes], &[0; 8]);
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        !matches!(engine.backend, ChaChaBackend::Portable(_))
    }

    #[test]
    fn chacha_engine_uses_rustcrypto_only_for_32_byte_keys_at_20_rounds_with_the_feature() {
        let rustcrypto = cfg!(feature = "rustcrypto");
        assert_eq!(on_rustcrypto(ChaChaEngine::new(), 32), rustcrypto);
        assert!(!on_rustcrypto(ChaChaEngine::new(), 16));
        assert!(!on_rustcrypto(ChaChaEngine::with_rounds(12).unwrap(), 32));
    }
}
