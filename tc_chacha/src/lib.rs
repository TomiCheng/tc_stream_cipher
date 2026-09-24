//! ChaCha, IETF ChaCha20 (RFC 8439) and XChaCha20 stream ciphers.
//!
//! Every engine implements the [`tc_stream_cipher`] traits and takes its key
//! and nonce through any container that implements both
//! [`KeyParams`](tc_stream_cipher::KeyParams) and
//! [`IvParams`](tc_stream_cipher::IvParams), such as
//! [`KeyWithIvRef`](tc_stream_cipher::KeyWithIvRef).
//!
//! # Choosing an engine
//!
//! [`ChaChaEngine`], [`ChaCha7539Engine`] and [`XChaCha20Engine`] pick their
//! backend: RustCrypto's `chacha20`, which uses SIMD where the processor has
//! it, when the `rustcrypto` Cargo feature is enabled and covers the request,
//! otherwise the portable engines. Enabling the feature never changes which
//! keys, nonces or round counts are accepted: 16-byte keys and reduced round
//! counts, which RustCrypto lacks, stay on [`ChaChaPortableEngine`]. Every
//! engine is constant time. For explicit selection, the portable engines are
//! always available, and `ChaChaRustCryptoEngine`,
//! `ChaCha7539RustCryptoEngine` and `XChaCha20RustCryptoEngine` are available
//! with the `rustcrypto` feature.
//!
//! # Example
//!
//! The first keystream bytes of RFC 8439's appendix A.1 test vector 1, an
//! all-zero key and nonce:
//!
//! ```
//! use tc_chacha::ChaCha7539Engine;
//! use tc_stream_cipher::{CipherDirection, KeyWithIvRef, StreamCipher, StreamCipherInit};
//!
//! let (key, nonce) = ([0u8; 32], [0u8; 12]);
//! let mut engine = ChaCha7539Engine::new();
//! engine.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &nonce))?;
//! let mut keystream = [0u8; 8];
//! assert_eq!(engine.process_bytes(&[0; 8], &mut keystream)?, 8);
//! assert_eq!(keystream, [0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! Every engine starts the keystream at block zero, whereas RFC 8439's
//! encryption examples start at block one, leaving block zero for the
//! Poly1305 key. The crate provides no authentication: never reuse a key and
//! nonce pair, and use an AEAD such as ChaCha20-Poly1305 to protect messages.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod chacha;
mod chacha7539_portable_engine;
mod chacha_portable_engine;
mod engine;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod xchacha20_portable_engine;

pub use chacha_portable_engine::ChaChaPortableEngine;
pub use chacha7539_portable_engine::ChaCha7539PortableEngine;
pub use engine::{ChaCha7539Engine, ChaChaEngine, XChaCha20Engine};
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::{
    ChaCha7539RustCryptoEngine, ChaChaRustCryptoEngine, XChaCha20RustCryptoEngine,
};
pub use xchacha20_portable_engine::XChaCha20PortableEngine;

/// Round count of ChaCha20, used unless
/// [`ChaChaEngine::with_rounds`] picks another.
pub const DEFAULT_ROUNDS: usize = 20;
/// Keystream block length in bytes.
pub const BLOCK_BYTES: usize = 64;
