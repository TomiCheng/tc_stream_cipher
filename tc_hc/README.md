# tc_hc

[![crates.io](https://img.shields.io/crates/v/tc_hc.svg)](https://crates.io/crates/tc_hc)
[![docs.rs](https://docs.rs/tc_hc/badge.svg)](https://docs.rs/tc_hc)
[![CI](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The HC-128 and HC-256 stream ciphers, ported from Bouncy Castle C# and
implementing the [`tc_stream_cipher`](https://crates.io/crates/tc_stream_cipher)
traits. Both index tables with secret state, so neither is constant time; the
crate exists for Bouncy Castle compatibility. Prefer ChaCha for new protocols.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_stream_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize) only.

Requires Rust 1.85 or later (edition 2024).

## Types

- `Hc128Engine` — HC-128 (eSTREAM): a 16-byte key and a 16-byte IV; variable
  time.
- `Hc256Engine` — HC-256: a 16- or 32-byte key and an IV of at least 16 bytes;
  variable time.

As in Bouncy Castle, `Hc256Engine` repeats a 16-byte key to 32 bytes, fills an
IV shorter than 32 bytes from its start, and uses only the first 32 bytes of a
longer IV. Another key or IV length returns `InitError::InvalidKeyLength` or
`InitError::InvalidIvLength` and keeps the previous key, IV and position. The
direction is ignored, since both apply the same keystream. `process_bytes`
XORs the input into the start of the output and returns the input length. It
returns `StreamError::NotInitialised` before `init` and
`StreamError::BufferTooShort` for an output shorter than the input; neither
moves the position.

`Display` writes `"HC-128"` or `"HC-256"` without inspecting key material. Each
engine has its length constants (`KEY_BYTES`, plus `MIN_IV_BYTES` and
`IV_BYTES` on HC-256), implements `Default` and has `const fn new`.

## Usage

```toml
[dependencies]
tc_hc = "0.1.0"
tc_stream_cipher = "0.1.0"
```

This example checks the first keystream bytes of HC-128's all-zero test
vector, then encrypts and decrypts a message:

```rust
use tc_hc::Hc128Engine;
use tc_stream_cipher::{CipherDirection, KeyWithIvRef, StreamCipher, StreamCipherInit};

let (key, iv) = ([0u8; 16], [0u8; 16]);
let params = KeyWithIvRef::new(&key, &iv);
let mut engine = Hc128Engine::new();
engine
    .init(CipherDirection::Encrypt, &params)
    .expect("HC-128 accepts a 16-byte key and a 16-byte IV");
let mut keystream = [0u8; 4];
assert_eq!(engine.process_bytes(&[0; 4], &mut keystream), Ok(4));
assert_eq!(keystream, [0x82, 0x00, 0x15, 0x73]);

engine.reset();
let mut ciphertext = [0u8; 5];
assert_eq!(engine.process_bytes(b"hello", &mut ciphertext), Ok(5));
engine.init(CipherDirection::Decrypt, &params).unwrap();
let mut plaintext = [0u8; 5];
assert_eq!(engine.process_bytes(&ciphertext, &mut plaintext), Ok(5));
assert_eq!(&plaintext, b"hello");
```

## Security

Neither engine is constant time. Every keystream step reads the `p` and `q`
tables at positions taken from the secret state, and HC-256 adds a cross
lookup between them, so the memory access pattern depends on secrets and can
leak where a cache is shared with an attacker. There is no constant-time form
of HC. Everything else is 32-bit additions, XORs and fixed rotations, and the
engines branch only on lengths and the keystream position.

The engines wipe the key, the IV and both tables on drop, and the key
schedule's scratch once used. Wiping does not reach the caller's key buffer or
copies left in registers and on the stack.

This is a stream-cipher primitive, not a message-encryption format. It
supplies no authentication, and a key and IV pair must never be reused.

## Validation

The engines are tested against the HC-128 and HC-256 vectors from the
designer's specifications, and HC-256 against Bouncy Castle's handling of
16-byte keys and IVs of 16 to 48 bytes. Contract tests cover error state, a
rejected `init` keeping the previous key and position, agreement between
chunked and bulk processing after `reset`, and both directions.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_hc --locked
cargo clippy -p tc_hc --all-targets --locked -- -D warnings
cargo fmt -p tc_hc --check
cargo doc -p tc_hc --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_hc --list --locked
cargo publish -p tc_hc --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
