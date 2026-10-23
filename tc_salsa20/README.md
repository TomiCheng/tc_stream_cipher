# tc_salsa20

[![crates.io](https://img.shields.io/crates/v/tc_salsa20.svg)](https://crates.io/crates/tc_salsa20)
[![docs.rs](https://docs.rs/tc_salsa20/badge.svg)](https://docs.rs/tc_salsa20)
[![CI](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The Salsa20 and XSalsa20 stream ciphers, ported from Bouncy Castle C#, with
portable and RustCrypto engines. Every engine implements the
[`tc_stream_cipher`](https://crates.io/crates/tc_stream_cipher) traits, and a
selecting engine for each variant uses RustCrypto where the build provides it
and it covers the request. Every engine is constant time.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_stream_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), and on RustCrypto's
[`salsa20`](https://crates.io/crates/salsa20) and
[`cipher`](https://crates.io/crates/cipher) only with the default-off
`rustcrypto` feature.

Requires Rust 1.85 or later (edition 2024) for the default build. The optional
`rustcrypto` feature follows the minimum Rust version of the `salsa20` and
`cipher` crates instead, which is 1.85 for `salsa20` 0.11.0 and `cipher`
0.5.2.

## Types

- `Salsa20Engine` — Salsa20 on the RustCrypto engine with `rustcrypto` for a
  32-byte key at 20 rounds, otherwise on the portable engine; constant time.
- `Xsalsa20Engine` — XSalsa20 on the RustCrypto engine with `rustcrypto`,
  otherwise on the portable engine; constant time.
- `Salsa20PortableEngine`, `Xsalsa20PortableEngine` — portable Rust; constant
  time.
- `Salsa20RustCryptoEngine`, `Xsalsa20RustCryptoEngine` (`rustcrypto`) —
  RustCrypto's `salsa20`; constant time, 32-byte keys and 20 rounds only.

Salsa20 takes a 16- or 32-byte key and an 8-byte IV, with an even round count,
20 unless `Salsa20Engine::with_rounds` or `Salsa20PortableEngine::with_rounds`
picks another; 8 and 12 are the reduced-round variants, and a zero or odd
count returns `InitError::InvalidRounds`. XSalsa20 takes a 32-byte key and a
24-byte IV: HSalsa20 derives a subkey from the key and the first 16 IV bytes,
and 20-round Salsa20 runs on the rest.

Another key or IV length returns `InitError::InvalidKeyLength` or
`InitError::InvalidIvLength` and keeps the previous key, IV and position. The
direction is ignored, since both apply the same keystream, which starts at
block zero. `process_bytes` XORs the input into the start of the output and
returns the input length. It returns `StreamError::NotInitialised` before
`init` and `StreamError::BufferTooShort` for an output shorter than the input;
errors leave the output and the position unchanged. One key and IV give at
most 2^70 bytes, as in Bouncy Castle: past that the portable engines return
`StreamError::MaxBytesExceeded` and the RustCrypto engines
`StreamError::CounterExhausted`; neither is reachable in practice.

`Display` writes `"Salsa20"`, or `"Salsa20/"` and the round count for other
counts as Bouncy Castle does, or `"XSalsa20"`, without inspecting key
material. Each engine has `KEY_BYTES` and `IV_BYTES` constants, the Salsa20
engines also `DEFAULT_ROUNDS`, and each implements `Default` and has
`const fn new`.

## Features

- `rustcrypto` (off by default) — adds the two RustCrypto engines, which the
  selecting engines then use wherever they cover the request; pulls in the
  `salsa20` and `cipher` crates and their minimum Rust version.

Enabling the feature never changes which keys, IVs or round counts are
accepted: 16-byte keys and reduced round counts stay on
`Salsa20PortableEngine`.

## Usage

```toml
[dependencies]
tc_salsa20 = "0.1.0"
tc_stream_cipher = "0.1.0"
```

This example checks the first keystream bytes of Bouncy Castle's Salsa20
vector for a 128-bit key, then encrypts and decrypts a message:

```rust
use tc_salsa20::Salsa20Engine;
use tc_stream_cipher::{CipherDirection, KeyWithIvRef, StreamCipher, StreamCipherInit};

let mut key = [0u8; 16];
key[0] = 0x80;
let iv = [0u8; 8];
let params = KeyWithIvRef::new(&key, &iv);
let mut engine = Salsa20Engine::new();
engine
    .init(CipherDirection::Encrypt, &params)
    .expect("Salsa20 accepts a 16-byte key and an 8-byte IV");
let mut keystream = [0u8; 4];
assert_eq!(engine.process_bytes(&[0; 4], &mut keystream), Ok(4));
assert_eq!(keystream, [0x4d, 0xfa, 0x5e, 0x48]);

engine.reset();
let mut ciphertext = [0u8; 5];
assert_eq!(engine.process_bytes(b"hello", &mut ciphertext), Ok(5));
engine.init(CipherDirection::Decrypt, &params).unwrap();
let mut plaintext = [0u8; 5];
assert_eq!(engine.process_bytes(&ciphertext, &mut plaintext), Ok(5));
assert_eq!(&plaintext, b"hello");
```

## Security

Every engine is constant time. Salsa20 uses only 32-bit additions, XORs and
fixed rotations, and the engines branch only on lengths, the round count and
the keystream position, which are public. The selecting engines choose their
backend from the key length and the round count, and RustCrypto chooses its
backend from the processor's features, all of which are public.

The portable engines wipe their state words and current keystream block on
drop, and each block's scratch and XSalsa20's subkey derivation scratch once
used. The RustCrypto engines wipe the cipher state and its buffered keystream
through the `zeroize` features of `salsa20` and `cipher`. Wiping does not
reach the caller's key buffer or copies left in registers and on the stack.

This is a stream-cipher primitive, not a message-encryption format. It
supplies no authentication, and a key and IV pair must never be reused. Prefer
ChaCha, Salsa20's successor, for new protocols.

## Benchmarks

Key setup and keystream throughput for the portable and RustCrypto engines,
and the commands to reproduce them, are in [BENCHES.md](BENCHES.md).

## Validation

The engines are tested against Bouncy Castle's Salsa20 vectors for a 128-bit
key at 20, 12 and 8 rounds and for a 256-bit key past 64 KiB, and against its
XSalsa20 vector. Contract tests cover error state, round-count validation, a
rejected `init` keeping the previous key and position, agreement between
chunked, bulk and single-byte processing after `reset`, and both directions.
A unit test drives the byte limit to its end, and another checks that
`Salsa20Engine` uses RustCrypto only for 32-byte keys at 20 rounds. With
`rustcrypto`, the vectors run through the RustCrypto engines too, and the
portable and RustCrypto engines are cross-checked across chunking and `reset`.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_salsa20 --locked
cargo test -p tc_salsa20 --locked --features rustcrypto
cargo clippy -p tc_salsa20 --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_salsa20 --check
cargo doc -p tc_salsa20 --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_salsa20 --list --locked
cargo publish -p tc_salsa20 --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
benchmark results, the source, the integration tests and the benchmark. It
must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
