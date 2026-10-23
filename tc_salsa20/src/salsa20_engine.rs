use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

use crate::Salsa20PortableEngine;
#[cfg(feature = "rustcrypto")]
use crate::Salsa20RustCryptoEngine;
use crate::salsa;
use crate::salsa20_portable_engine::valid_rounds;

/// The backend running the current key.
enum Backend {
    #[cfg(feature = "rustcrypto")]
    RustCrypto(Salsa20RustCryptoEngine),
    Portable(Salsa20PortableEngine),
}

/// Salsa20 (Bernstein, 2005), as Bouncy Castle's `Salsa20Engine`: a 16- or
/// 32-byte key and an 8-byte IV, with an even round count, 20 unless
/// [`with_rounds`](Self::with_rounds) picks another.
///
/// With the `rustcrypto` feature, a 32-byte key at 20 rounds runs on
/// RustCrypto's `Salsa20`. RustCrypto has no 16-byte key, and reduced round
/// counts stay on [`Salsa20PortableEngine`] too, so the feature never changes
/// which keys and round counts work. The only difference is how the 2^70-byte
/// limit per IV is reported: `MaxBytesExceeded` on the portable engine and
/// `CounterExhausted` on RustCrypto; neither is reachable in practice.
///
/// **Constant time:** both backends use only 32-bit additions, XORs and fixed
/// rotations, and the backend is chosen from the key length and the round
/// count, which are public. Keystream state is wiped on drop; the caller's key
/// and copies left in registers or on the stack are not.
pub struct Salsa20Engine {
    rounds: usize,
    backend: Backend,
}

impl Salsa20Engine {
    /// Accepted key lengths in bytes.
    pub const KEY_BYTES: [usize; 2] = Salsa20PortableEngine::KEY_BYTES;
    /// IV length in bytes.
    pub const IV_BYTES: usize = Salsa20PortableEngine::IV_BYTES;
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

    const fn build(rounds: usize) -> Self {
        Self {
            rounds,
            backend: Backend::Portable(Salsa20PortableEngine::build(rounds)),
        }
    }

    /// A fresh backend for a key of `key_bytes` bytes.
    #[cfg(feature = "rustcrypto")]
    fn backend_for(&self, key_bytes: usize) -> Backend {
        if self.rounds == salsa::DEFAULT_ROUNDS && key_bytes == Salsa20RustCryptoEngine::KEY_BYTES {
            Backend::RustCrypto(Salsa20RustCryptoEngine::new())
        } else {
            Backend::Portable(Salsa20PortableEngine::build(self.rounds))
        }
    }

    /// A fresh backend for a key of `key_bytes` bytes.
    #[cfg(not(feature = "rustcrypto"))]
    fn backend_for(&self, _key_bytes: usize) -> Backend {
        Backend::Portable(Salsa20PortableEngine::build(self.rounds))
    }
}

impl Default for Salsa20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Salsa20Engine {
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

impl StreamCipher for Salsa20Engine {
    type Error = StreamError;

    /// XORs `input` with the next keystream byte; see the backend for the
    /// errors. Constant time.
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        match &mut self.backend {
            #[cfg(feature = "rustcrypto")]
            Backend::RustCrypto(engine) => engine.return_byte(input),
            Backend::Portable(engine) => engine.return_byte(input),
        }
    }

    /// XORs `input` with the keystream into the start of `output` and returns
    /// `input.len()`; errors leave `output` and the position unchanged. Constant
    /// time; branches only on the lengths and the position.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        match &mut self.backend {
            #[cfg(feature = "rustcrypto")]
            Backend::RustCrypto(engine) => engine.process_bytes(input, output),
            Backend::Portable(engine) => engine.process_bytes(input, output),
        }
    }

    /// Returns to the start of the keystream for the current key and IV.
    /// Constant time.
    fn reset(&mut self) {
        match &mut self.backend {
            #[cfg(feature = "rustcrypto")]
            Backend::RustCrypto(engine) => engine.reset(),
            Backend::Portable(engine) => engine.reset(),
        }
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Salsa20Engine {
    type Error = InitError;

    /// Installs a 16- or 32-byte key and an 8-byte IV on the backend that covers
    /// them, and starts the keystream at block zero. The direction is ignored. A
    /// rejected length leaves the previous backend, key, IV and position in place.
    /// Constant time; branches only on the lengths and the round count.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let mut backend = self.backend_for(params.key().len());
        match &mut backend {
            #[cfg(feature = "rustcrypto")]
            Backend::RustCrypto(engine) => engine.init(direction, params)?,
            Backend::Portable(engine) => engine.init(direction, params)?,
        }
        self.backend = backend;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tc_stream_cipher::{CipherDirection, KeyWithIvRef, StreamCipherInit};

    use super::{Backend, Salsa20Engine};

    /// Whether `engine` ran on RustCrypto after keying it with `key_bytes`.
    fn on_rustcrypto(mut engine: Salsa20Engine, key_bytes: usize) -> bool {
        let params = KeyWithIvRef::new(&[0; 32][..key_bytes], &[0; 8]);
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        !matches!(engine.backend, Backend::Portable(_))
    }

    #[test]
    fn salsa20_engine_uses_rustcrypto_only_for_32_byte_keys_at_20_rounds_with_the_feature() {
        let rustcrypto = cfg!(feature = "rustcrypto");
        assert_eq!(on_rustcrypto(Salsa20Engine::new(), 32), rustcrypto);
        assert!(!on_rustcrypto(Salsa20Engine::new(), 16));
        assert!(!on_rustcrypto(Salsa20Engine::with_rounds(12).unwrap(), 32));
    }
}
