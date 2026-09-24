# Changelog

All notable changes to `tc_stream_cipher` are documented in this file.

## 0.1.0 - 2026-09-24

Initial release.

### Added

- `StreamCipherInit<P>`, whose `init` validates and installs parameters for
  one `CipherDirection`, and `StreamCipher`, whose `process_bytes` and
  `return_byte` apply the keystream and whose `reset` returns to its start.
  Each trait has its own associated error type, and the two are separate so
  generic callers can require exactly the capabilities they use and
  `StreamCipher` stays usable as a trait object. The parameter type `P` is
  open: a key container or an engine-specific type.
- `KeyParams`, which borrows key bytes, and `IvParams`, which borrows IV
  (nonce) bytes, kept separate for ciphers that take no IV. Neither imposes an
  ownership or wiping policy.
- Six containers: `KeyRef` and `KeyWithIvRef` borrow slices, `KeyFixed<N>` and
  `KeyWithIvFixed<K, I>` own arrays without an allocator, and `KeyOwned` and
  `KeyWithIvOwned` take ownership of vectors without cloning them. The owning
  containers implement `tc_zeroize::Zeroize` and `ZeroizeOnDrop` and wipe
  their storage, IV included, on drop.
- `InitError` and `StreamError`, reusable `#[non_exhaustive]` error enums for
  invalid key and IV lengths and round counts, processing before
  initialization, output buffers shorter than the input, and exhausted byte
  limits and block counters. Both implement `Display` and
  `core::error::Error`.
- A default-off `alloc` feature that adds `KeyOwned` and `KeyWithIvOwned`
  through the sysroot `alloc` crate and enables `tc_zeroize/alloc`.
- `no_std` builds without `unsafe` code, enforced by `#![forbid(unsafe_code)]`;
  missing public documentation is rejected by `#![deny(missing_docs)]`. The
  crate documentation carries an executable example implementing both traits.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends only on `tc_zeroize` 0.1.
- The traits make no constant-time promise; key and IV validation, keystream
  limits, the state after a rejected initialization and timing are defined by
  each engine.
- Wiping reaches only a container's own storage, not caller-held copies,
  engine state, or temporaries in registers and on the stack. Drop-based
  wiping requires the destructor to run.
- The crate supplies no authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
