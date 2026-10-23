# Changelog

All notable changes to `tc_salsa20` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- Salsa20 and XSalsa20 through the `tc_stream_cipher` traits, accepting any
  container that implements `KeyParams` and `IvParams`. Salsa20 takes a 16- or
  32-byte key and an 8-byte IV; XSalsa20 takes a 32-byte key and a 24-byte IV
  and derives a subkey with HSalsa20. Every engine rejects other lengths with
  `InitError::InvalidKeyLength` or `InitError::InvalidIvLength` while keeping
  its previous key, IV and position, returns `StreamError::NotInitialised`
  before a key is installed and `StreamError::BufferTooShort` for an output
  shorter than the input, and leaves the output and position unchanged on
  every error. The keystream starts at block zero, and the direction is
  ignored.
- `Salsa20Engine` and `Xsalsa20Engine`, which pick their backend: the
  RustCrypto engines with the `rustcrypto` feature, otherwise the portable
  engines. `Salsa20Engine` stays on the portable engine for 16-byte keys and
  reduced round counts, which RustCrypto lacks, so the feature never changes
  which keys, IVs or round counts are accepted.
- `Salsa20PortableEngine` and `Xsalsa20PortableEngine` in portable Rust.
  `Salsa20Engine::with_rounds` and `Salsa20PortableEngine::with_rounds` accept
  any positive even round count, including Salsa20/8 and Salsa20/12, and
  return `InitError::InvalidRounds` otherwise.
- `Salsa20RustCryptoEngine` and `Xsalsa20RustCryptoEngine`, behind the
  default-off `rustcrypto` feature, backed by RustCrypto's `salsa20` crate
  with the `zeroize` features of `salsa20` and `cipher`.
- Bouncy Castle's keystream limit of 2^70 bytes per IV: the portable engines
  return `StreamError::MaxBytesExceeded` and the RustCrypto engines
  `StreamError::CounterExhausted`, each checked before any output is written.
- `Display` for every engine, writing `Salsa20` (or `Salsa20/` and the round
  count) or `XSalsa20`; `KEY_BYTES` and `IV_BYTES` on every engine and
  `DEFAULT_ROUNDS` on the Salsa20 engines.
- The portable engines wipe their state words and current keystream block on
  drop, and their block and subkey scratch once used. The RustCrypto engines
  wipe the cipher state and its buffered keystream on drop.
- Tests against Bouncy Castle's Salsa20 vectors at 20, 12 and 8 rounds and
  past 64 KiB and its XSalsa20 vector; contract tests of error state, round
  counts, rejected `init`, chunking, `reset` and both directions; unit tests of
  the byte limit and of backend selection; and cross-checks between the
  portable and RustCrypto engines.
- Criterion benchmarks for key setup and keystream throughput on the portable
  and RustCrypto engines.
- `no_std` builds without `unsafe` code, enforced by `#![forbid(unsafe_code)]`;
  missing public documentation is rejected by `#![deny(missing_docs)]`.

### Compatibility

- Requires Rust 1.85 or later for the default build and uses Rust edition
  2024. The `rustcrypto` feature follows the minimum Rust version of the
  `salsa20` and `cipher` crates, which is 1.85 for `salsa20` 0.11.0 and
  `cipher` 0.5.2; a later release of either may raise it without a
  `tc_salsa20` release.
- Depends on `tc_stream_cipher` 0.1 and `tc_zeroize` 0.1, and on `salsa20`
  0.11 and `cipher` 0.5 only with `rustcrypto`.
- Every engine is constant time: Salsa20 uses only 32-bit additions, XORs and
  fixed rotations, and the engines branch only on lengths, the round count and
  the keystream position.
- Wiping reaches only the engines' own state, not the caller's key buffer or
  copies left in registers and on the stack.
- The crate supplies no authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
