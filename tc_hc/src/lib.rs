//! The HC-128 and HC-256 stream ciphers on the `tc_stream_cipher` traits.
//!
//! Both index tables with secret state, so neither is constant time; they are
//! kept for Bouncy Castle compatibility. Prefer ChaCha for new protocols.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod hc128_engine;
mod hc256_engine;

pub use hc128_engine::Hc128Engine;
pub use hc256_engine::Hc256Engine;
