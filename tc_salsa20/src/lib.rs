//! The Salsa20 and XSalsa20 stream ciphers on the `tc_stream_cipher` traits.
//!
//! Both are ARX constructions (32-bit additions, rotations and XORs) and
//! constant time. Prefer ChaCha, Salsa20's successor, for new protocols.
//!
//! [`Salsa20Engine`] and [`Xsalsa20Engine`] pick their backend: with the
//! `rustcrypto` feature, the lengths and round counts RustCrypto covers go to
//! the `salsa20` crate and the rest stay on the portable engines, so the
//! feature never changes which parameters are accepted. Each backend can also be
//! used directly.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod salsa;
mod salsa20_engine;
mod salsa20_portable_engine;
mod xsalsa20_engine;
mod xsalsa20_portable_engine;

#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::{Salsa20RustCryptoEngine, Xsalsa20RustCryptoEngine};
pub use salsa20_engine::Salsa20Engine;
pub use salsa20_portable_engine::Salsa20PortableEngine;
pub use xsalsa20_engine::Xsalsa20Engine;
pub use xsalsa20_portable_engine::Xsalsa20PortableEngine;
