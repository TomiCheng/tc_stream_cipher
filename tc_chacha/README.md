# tc_chacha

[![crates.io](https://img.shields.io/crates/v/tc_chacha.svg)](https://crates.io/crates/tc_chacha)
[![docs.rs](https://docs.rs/tc_chacha/badge.svg)](https://docs.rs/tc_chacha)
[![CI](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The original ChaCha, IETF ChaCha20 (RFC 8439) and XChaCha20 stream ciphers,
with portable and RustCrypto engines. Every engine implements the
[`tc_stream_cipher`](https://crates.io/crates/tc_stream_cipher) traits, and a
selecting engine for each variant uses RustCrypto where the build provides it
and it covers the request. Every engine is constant time.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_stream_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), and on RustCrypto's
[`chacha20`](https://crates.io/crates/chacha20) and
[`cipher`](https://crates.io/crates/cipher) only with the default-off
`rustcrypto` feature.

Requires Rust 1.85 or later (edition 2024) for the default build. The optional
`rustcrypto` feature follows the minimum Rust version of the `chacha20` and
`cipher` crates instead, which is 1.85 for `chacha20` 0.10.2 and `cipher`
0.5.2.

## Types

- `ChaChaEngine` — the original ChaCha on the RustCrypto engine with
  `rustcrypto` for a 32-byte key at 20 rounds, otherwise on the portable
  engine; constant time.
- `ChaCha7539Engine` — IETF ChaCha20 on the RustCrypto engine with
  `rustcrypto`, otherwise on the portable engine; constant time.
- `XChaCha20Engine` — XChaCha20, chosen the same way; constant time.
- `ChaChaPortableEngine`, `ChaCha7539PortableEngine`, `XChaCha20PortableEngine`
  — portable Rust; constant time.
- `ChaChaRustCryptoEngine`, `ChaCha7539RustCryptoEngine`,
  `XChaCha20RustCryptoEngine` (`rustcrypto`) — RustCrypto's `chacha20`, which
  uses SIMD where the processor has it; constant time, 32-byte keys and 20
  rounds only.

The original ChaCha takes a 16- or 32-byte key and an 8-byte nonce, with a
64-bit block counter and an even round count, 20 unless
`ChaChaEngine::with_rounds` or `ChaChaPortableEngine::with_rounds` picks
another; 8 and 12 are the reduced-round variants, and a zero or odd count
returns `InitError::InvalidRounds`. IETF ChaCha20 takes a 32-byte key and a
12-byte nonce, with a 32-bit block counter. XChaCha20 takes a 32-byte key and a
24-byte nonce, long enough to choose at random: HChaCha20 derives a subkey from
the key and the first 16 nonce bytes, and IETF ChaCha20 runs on the rest.

Another key or nonce length returns `InitError::InvalidKeyLength` or
`InitError::InvalidIvLength` and keeps the previous key, nonce and position.
The direction is ignored, since both apply the same keystream, which starts at
block zero. `process_bytes` XORs the input into the start of the output and
returns the input length, leaving any longer tail of the output untouched. It
returns `StreamError::NotInitialised` before `init`,
`StreamError::BufferTooShort` for an output shorter than the input, and
`StreamError::CounterExhausted` once IETF ChaCha20 or XChaCha20 would pass 2^32
blocks (256 GiB); errors leave the output and the position unchanged. The
original ChaCha stops just under 2^69 bytes with `StreamError::MaxBytesExceeded`
on the portable engine, and at 2^70 bytes on RustCrypto; neither is reachable
in practice.

`Display` writes `"ChaCha20"`, or `"ChaCha"` and the round count,
`"ChaCha7539"` or `"XChaCha20"` without inspecting key material. Each engine
has `KEY_BYTES` and `IV_BYTES` constants, implements `Default` and has
`const fn new`. The crate constants `DEFAULT_ROUNDS` and `BLOCK_BYTES` hold the
default round count, `20`, and the keystream block length, `64`.

## Features

- `rustcrypto` (off by default) — adds the three RustCrypto engines, which the
  selecting engines then use wherever they cover the request; pulls in the
  `chacha20` and `cipher` crates and their minimum Rust version.

Enabling the feature never changes which keys, nonces or round counts are
accepted: 16-byte keys and reduced round counts, which RustCrypto lacks, stay
on `ChaChaPortableEngine`.

## Usage

```toml
[dependencies]
tc_chacha = "0.1.0"
tc_stream_cipher = "0.1.0"
```

This example checks the first keystream bytes of RFC 8439's appendix A.1 test
vector 1, an all-zero key and nonce, then encrypts and decrypts a message:

```rust
use tc_chacha::ChaCha7539Engine;
use tc_stream_cipher::{CipherDirection, KeyWithIvRef, StreamCipher, StreamCipherInit};

let (key, nonce) = ([0u8; 32], [0u8; 12]);
let params = KeyWithIvRef::new(&key, &nonce);
let mut engine = ChaCha7539Engine::new();
engine
    .init(CipherDirection::Encrypt, &params)
    .expect("IETF ChaCha20 accepts a 32-byte key and a 12-byte nonce");
let mut keystream = [0u8; 8];
assert_eq!(engine.process_bytes(&[0; 8], &mut keystream), Ok(8));
assert_eq!(keystream, [0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90]);

engine.reset();
let mut ciphertext = [0u8; 5];
assert_eq!(engine.process_bytes(b"hello", &mut ciphertext), Ok(5));
engine.init(CipherDirection::Decrypt, &params).unwrap();
let mut plaintext = [0u8; 5];
assert_eq!(engine.process_bytes(&ciphertext, &mut plaintext), Ok(5));
assert_eq!(&plaintext, b"hello");
```

The crate documentation carries an executable example.

## Security

Every engine is constant time. ChaCha uses only 32-bit additions, XORs and
fixed rotations, and the engines branch only on lengths, the round count and
the keystream position, which are public. The selecting engines choose their
backend from the key length and the round count, and RustCrypto chooses its
SIMD backend from the processor's features, all of which are public.

The portable engines wipe their key words and current keystream block on drop,
and XChaCha20 wipes its subkey once it is installed. The RustCrypto engines
wipe the cipher state and its buffered keystream through the `zeroize`
features of `chacha20` and `cipher`. Wiping does not reach the caller's key
buffer or copies left in registers and on the stack.

This is a stream-cipher primitive, not a message-encryption format. It
supplies no authentication. Never reuse a key and nonce pair, and use an AEAD
such as ChaCha20-Poly1305 to protect messages. RFC 8439's encryption examples
start the keystream at block one, leaving block zero for the Poly1305 key;
these engines start at block zero.

## Benchmarks

Key setup and keystream throughput for the portable and RustCrypto engines,
and the commands to reproduce them, are in [BENCHES.md](BENCHES.md).

## Validation

The engines are tested against the original ChaCha vectors from the eSTREAM
reference implementation that Bouncy Castle's tests use: ChaCha20 with a
128-bit key at four offsets and with a 256-bit key past 64 KiB, and ChaCha12
and ChaCha8. IETF ChaCha20 is tested against the RFC 8439 encryption example,
and XChaCha20 against the XChaCha draft's encryption example and HChaCha20
vector. Contract tests cover error state, untouched output on errors, preserved
output tails, agreement between chunked, bulk and single-byte processing, both
directions, round-count validation, and `ChaChaEngine` switching backends as
the key length changes. Unit tests drive the byte limit and the 32-bit counter
to their ends. With `rustcrypto`, the portable engines are cross-checked
against RustCrypto's `chacha20` on pseudorandom keys, nonces, lengths and
chunkings.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_chacha --locked
cargo test -p tc_chacha --locked --features rustcrypto
cargo clippy -p tc_chacha --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_chacha --check
cargo doc -p tc_chacha --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_chacha --list --locked
cargo publish -p tc_chacha --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
benchmark results, the source, the integration tests and the benchmark. It must
not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
