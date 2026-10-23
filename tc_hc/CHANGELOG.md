# Changelog

All notable changes to `tc_hc` are documented in this file.

## 0.1.0 - 2026-10-24

Initial release.

### Added

- HC-128 and HC-256 through the `tc_stream_cipher` traits, accepting any
  container that implements `KeyParams` and `IvParams`. `Hc128Engine` takes a
  16-byte key and a 16-byte IV; `Hc256Engine` takes a 16- or 32-byte key and
  an IV of at least 16 bytes, filled out to 32 bytes as Bouncy Castle does.
  Both reject other lengths with `InitError::InvalidKeyLength` or
  `InitError::InvalidIvLength` while keeping their previous key, IV and
  position, return `StreamError::NotInitialised` before a key is installed and
  `StreamError::BufferTooShort` for an output shorter than the input, and
  ignore the direction.
- `Display` for both engines, writing `HC-128` or `HC-256`; length constants
  on both; `Default` and `const fn new`.
- Both engines wipe the key, the IV and both tables on drop, and the key
  schedule's scratch once used.
- Tests against the HC-128 and HC-256 vectors, Bouncy Castle's handling of
  short HC-256 keys and IVs, and contract tests of error state, rejected
  `init`, chunking, `reset` and both directions.
- `no_std` builds without `unsafe` code, enforced by `#![forbid(unsafe_code)]`;
  missing public documentation is rejected by `#![deny(missing_docs)]`.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_stream_cipher` 0.1 and `tc_zeroize` 0.1.
- Neither engine is constant time: HC looks up its tables at positions taken
  from the secret state. The crate exists for Bouncy Castle compatibility.
- Wiping reaches only the engines' own state, not the caller's key buffer or
  copies left in registers and on the stack.
- The crate supplies no authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
