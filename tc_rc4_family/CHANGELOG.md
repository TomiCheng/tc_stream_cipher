# Changelog

All notable changes to `tc_rc4_family` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- RC4, VMPC, VMPC-KSA3 and ISAAC through the `tc_stream_cipher` traits. RC4
  takes a key of 1 to 256 bytes and ISAAC a key of 0 to 1024 bytes, both
  without an IV; VMPC and VMPC-KSA3 take a key and an IV of 16 to 64 bytes
  each. Every engine rejects other lengths with `InitError::InvalidKeyLength`
  or `InitError::InvalidIvLength` while keeping its previous key, IV and
  position, returns `StreamError::NotInitialised` before a key is installed
  and `StreamError::BufferTooShort` for an output shorter than the input, and
  ignores the direction.
- `Rc4Engine`, which runs on `Rc4RustCryptoEngine` with the `rustcrypto`
  feature and on `Rc4PortableEngine` without it, chosen at compile time; both
  accept the same keys.
- `Rc4RustCryptoEngine`, behind the default-off `rustcrypto` feature, backed
  by RustCrypto's `rc4` crate with its `zeroize` feature. It keeps a copy of
  the key, wiped on drop, so that `reset` can rerun the key schedule.
- `Display` for every engine, writing `RC4`, `VMPC`, `VMPC-KSA3` or `ISAAC`;
  length constants on every engine; `Default` and `const fn new`.
- Every engine wipes its permutation or state, key, IV and buffered keystream
  on drop.
- Tests against Bouncy Castle's vectors, RFC 6229 and the classic RC4
  examples, Bouncy Castle's one-million-byte VMPC and VMPC-KSA3 checkpoints,
  and Bouncy Castle's ISAAC vectors; contract tests of error state, custom
  parameter types, dynamic dispatch, chunking, `reset` and both directions;
  and cross-checks between the portable and RustCrypto RC4 engines.
- A Criterion benchmark for RC4 key setup and keystream throughput on the
  portable and RustCrypto engines.
- `no_std` builds without `unsafe` code, enforced by `#![forbid(unsafe_code)]`;
  missing public documentation is rejected by `#![deny(missing_docs)]`.

### Compatibility

- Requires Rust 1.85 or later for the default build and uses Rust edition
  2024. The `rustcrypto` feature follows the minimum Rust version of the `rc4`
  crate, which is 1.85 for `rc4` 0.2.0; a later release may raise it without a
  `tc_rc4_family` release.
- Depends on `tc_stream_cipher` 0.1 and `tc_zeroize` 0.1, and on `rc4` 0.2
  only with `rustcrypto`.
- No engine is constant time: each reads its table at positions taken from
  the secret state. RC4 is broken; the crate exists for legacy data and Bouncy
  Castle compatibility.
- Wiping reaches only the engines' own state, not the caller's key buffer or
  copies left in registers and on the stack.
- The crate supplies no authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
