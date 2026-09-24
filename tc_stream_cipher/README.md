# tc_stream_cipher

[![crates.io](https://img.shields.io/crates/v/tc_stream_cipher.svg)](https://crates.io/crates/tc_stream_cipher)
[![docs.rs](https://docs.rs/tc_stream_cipher/badge.svg)](https://docs.rs/tc_stream_cipher)
[![CI](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Shared traits, error types and key and IV containers for stream ciphers.
Engine crates such as [`tc_chacha`](https://crates.io/crates/tc_chacha)
implement the traits, and generic code that applies a keystream names only the
capabilities it uses. The crate implements no algorithm or authentication.

It is `no_std`, contains no `unsafe` code, and depends only on
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), which wipes the owned
containers. A single, default-off `alloc` feature adds heap-backed containers
through the sysroot `alloc` crate.

Requires Rust 1.85 or later (edition 2024).

## Traits

- `StreamCipherInit<P>` — `init` installs a key and IV, or engine-specific
  parameters, for one direction.
- `StreamCipher` — `process_bytes` and `return_byte` apply the keystream;
  `reset` returns to its start.
- `KeyParams` — `key` borrows the key bytes.
- `IvParams` — `iv` borrows the IV (nonce) bytes.

Initialization and processing are separate traits so generic callers can state
exactly which capabilities they need, and `StreamCipher` stays usable as a
trait object. The key and the IV are separate traits because some stream
ciphers, such as RC4, take no IV. Accepted key and IV lengths, round counts,
keystream limits, the state left by a rejected initialization, and every
timing guarantee belong to the engine, not to these traits.

## Types

- `CipherDirection` — `Encrypt` or `Decrypt`.
- `InitError`, `StreamError` — reusable initialization and processing errors.
- `KeyRef` — borrows a key slice.
- `KeyFixed<N>` — owns a key array and wipes it on drop.
- `KeyOwned` (`alloc`) — owns a key vector and wipes it on drop.
- `KeyWithIvRef` — borrows a key slice and an IV slice.
- `KeyWithIvFixed<K, I>` — owns a key array and an IV array and wipes both on
  drop.
- `KeyWithIvOwned` (`alloc`) — owns a key vector and an IV vector and wipes
  both on drop.

Both error enums are `#[non_exhaustive]` and implement `Clone`, `Copy`, `Debug`,
`PartialEq`, `Eq`, `Display` and `core::error::Error`. Engines may use them as
their associated error types or expose more specific failures of their own.

Every container implements `KeyParams`, and the `KeyWithIv` containers also
implement `IvParams`. The owning containers implement `tc_zeroize::Zeroize`
and `tc_zeroize::ZeroizeOnDrop`, and wipe the IV along with the key although
it is not secret. No container validates algorithm-specific lengths; the
receiving engine does.

## Features

- `alloc` (off by default) — adds `KeyOwned` and `KeyWithIvOwned`; still
  `no_std`.

## Usage

Add the crate next to an engine crate:

```toml
[dependencies]
tc_stream_cipher = "0.1.0"
tc_chacha = "0.1.0"
```

`KeyOwned` and `KeyWithIvOwned` need the default-off `alloc` feature:

```toml
[dependencies]
tc_stream_cipher = { version = "0.1.0", features = ["alloc"] }
```

Import the traits to reach an engine's methods and pick a container:

```rust
use tc_chacha::ChaCha7539Engine;
use tc_stream_cipher::{CipherDirection, KeyWithIvFixed, StreamCipher, StreamCipherInit};

let params = KeyWithIvFixed::new([0x42; 32], [0x24; 12]);
let mut engine = ChaCha7539Engine::new();
engine
    .init(CipherDirection::Encrypt, &params)
    .expect("IETF ChaCha20 accepts a 32-byte key and a 12-byte nonce");
let mut ciphertext = [0; 5];
assert_eq!(engine.process_bytes(b"hello", &mut ciphertext), Ok(5));
```

The crate documentation has an executable example of implementing both traits
for an engine.

## Key handling and limitations

`KeyRef` and `KeyWithIvRef` leave the caller's bytes untouched; the caller owns
and wipes them. The owning containers wipe only their own storage. Wiping does
not reach the caller's original arrays, copies made before a vector was moved
in, engine state, or temporaries left in registers and on the stack. Drop-based
wiping requires the destructor to run.

The traits make no constant-time promise. Whether key setup and keystream
processing are constant time is documented by each engine. A stream cipher
alone provides confidentiality only: never reuse a key and IV pair, and use an
authenticated-encryption construction to protect messages.

## Validation

The crate documentation carries an executable example that implements both
traits and drives them through `KeyWithIvFixed` and `KeyWithIvRef`. Unit tests
cover the containers' accessors and wiping and the error messages. Missing
public documentation is rejected by a crate-level lint, and `unsafe` code is
forbidden. The ChaCha engines in `tc_chacha` exercise the traits and error
types against the RFC 8439, XChaCha and Bouncy Castle known-answer vectors.

Run these commands from the workspace root:

```text
cargo test -p tc_stream_cipher --locked
cargo test -p tc_stream_cipher --locked --features alloc
cargo clippy -p tc_stream_cipher --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_stream_cipher --check
cargo doc -p tc_stream_cipher --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_stream_cipher --list --locked
cargo publish -p tc_stream_cipher --dry-run --locked
```

The archive includes both license texts, this README, the changelog and the
source. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
