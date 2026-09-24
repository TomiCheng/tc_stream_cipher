# Changelog

All notable changes to `tc_chacha` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- The original ChaCha, IETF ChaCha20 (RFC 8439) and XChaCha20 through the
  `tc_stream_cipher` traits, accepting any container that implements
  `KeyParams` and `IvParams`. The original ChaCha takes a 16- or 32-byte key
  and an 8-byte nonce with a 64-bit block counter; IETF ChaCha20 takes a
  32-byte key and a 12-byte nonce with a 32-bit block counter; XChaCha20 takes
  a 32-byte key and a 24-byte nonce and derives a subkey with HChaCha20. Every
  engine rejects other lengths with `InitError::InvalidKeyLength` or
  `InitError::InvalidIvLength` while keeping its previous key, nonce and
  position, returns `StreamError::NotInitialised` before a key is installed
  and `StreamError::BufferTooShort` for an output shorter than the input, and
  leaves the output and position unchanged on every error. The keystream
  starts at block zero, and the direction is ignored.
- `ChaChaEngine`, `ChaCha7539Engine` and `XChaCha20Engine`, which pick their
  backend: the RustCrypto engines with the `rustcrypto` feature, otherwise the
  portable engines. `ChaChaEngine` stays on the portable engine for 16-byte
  keys and reduced round counts, which RustCrypto lacks, so the feature never
  changes which keys, nonces or round counts are accepted. Their types and
  APIs are the same under every configuration, and all have `const fn new`.
- `ChaChaPortableEngine`, `ChaCha7539PortableEngine` and
  `XChaCha20PortableEngine` in portable Rust. `ChaChaEngine::with_rounds` and
  `ChaChaPortableEngine::with_rounds` accept any positive even round count,
  including the reduced-round ChaCha8 and ChaCha12, and return
  `InitError::InvalidRounds` otherwise.
- `ChaChaRustCryptoEngine`, `ChaCha7539RustCryptoEngine` and
  `XChaCha20RustCryptoEngine`, behind the default-off `rustcrypto` feature,
  backed by RustCrypto's `chacha20` crate, which uses SIMD where the processor
  has it, with the `zeroize` features of `chacha20` and `cipher`.
- Keystream limits: IETF ChaCha20 and XChaCha20 return
  `StreamError::CounterExhausted` once a request would pass 2^32 blocks, and
  the portable original ChaCha returns `StreamError::MaxBytesExceeded` just
  before 2^69 bytes. Each limit is checked before any output is written.
- `Display` for every engine, writing `ChaCha` and the round count,
  `ChaCha7539` or `XChaCha20`; `KEY_BYTES` and `IV_BYTES` on every engine; and
  the crate constants `DEFAULT_ROUNDS` and `BLOCK_BYTES`.
- The portable engines wipe their key words and current keystream block on
  drop, and XChaCha20 wipes its subkey once it is installed. The RustCrypto
  engines wipe the cipher state and its buffered keystream on drop.
- Tests against the original ChaCha vectors from the eSTREAM reference
  implementation used by Bouncy Castle's tests, at 20, 12 and 8 rounds and
  past 64 KiB, the RFC 8439 encryption example, and the XChaCha draft's
  encryption example and HChaCha20 vector; contract tests of error state,
  untouched output, preserved output tails, chunking, both directions and
  backend switching for every engine; unit tests of both keystream limits;
  and cross-checks between the portable and RustCrypto engines on
  pseudorandom keys, nonces, lengths and chunkings.
- Criterion benchmarks for key setup and keystream throughput on the portable
  and RustCrypto engines, with results in `BENCHES.md`.
- `no_std` builds without `unsafe` code, enforced by `#![forbid(unsafe_code)]`;
  missing public documentation is rejected by `#![deny(missing_docs)]`.

### Compatibility

- Requires Rust 1.85 or later for the default build and uses Rust edition
  2024. The `rustcrypto` feature follows the minimum Rust version of the
  `chacha20` and `cipher` crates, which is 1.85 for `chacha20` 0.10.2 and
  `cipher` 0.5.2; a later release of either may raise it without a
  `tc_chacha` release.
- Depends on `tc_stream_cipher` 0.1 and `tc_zeroize` 0.1, and on `chacha20`
  0.10 and `cipher` 0.5 only with `rustcrypto`.
- Every engine is constant time: ChaCha uses only 32-bit additions, XORs and
  fixed rotations, and the engines branch only on lengths, the round count
  and the keystream position.
- Wiping reaches only the engines' own state, not the caller's key buffer or
  copies left in registers and on the stack.
- The crate supplies no authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
