# tc_stream_cipher

A Rust workspace for stream ciphers. It holds `tc_stream_cipher`, the shared
traits, errors and key and IV containers through which an engine is
initialized and applies its keystream, and the engine crates built on it:
`tc_chacha`. Each crate is published separately and keeps its own README,
changelog, and validation commands.

[![CI](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_stream_cipher`](tc_stream_cipher) | [![crates.io](https://img.shields.io/crates/v/tc_stream_cipher.svg)](https://crates.io/crates/tc_stream_cipher) [![docs.rs](https://docs.rs/tc_stream_cipher/badge.svg)](https://docs.rs/tc_stream_cipher) | Initialization and keystream processing traits, reusable error types, and key and IV containers that borrow, or own and wipe, their bytes. No algorithm or authentication. `no_std`, no `unsafe`, depends only on `tc_zeroize`; a default-off `alloc` feature adds vector-backed containers. |
| [`tc_chacha`](tc_chacha) | [![crates.io](https://img.shields.io/crates/v/tc_chacha.svg)](https://crates.io/crates/tc_chacha) [![docs.rs](https://docs.rs/tc_chacha/badge.svg)](https://docs.rs/tc_chacha) | The original ChaCha, IETF ChaCha20 (RFC 8439) and XChaCha20 with portable engines and selecting engines that use RustCrypto where it covers the request. Every engine is constant time. `no_std`, no allocator, no `unsafe`; depends on `tc_stream_cipher` and `tc_zeroize`. A default-off `rustcrypto` feature adds engines backed by RustCrypto's `chacha20`, which uses SIMD where the processor has it. |

`tc_stream_cipher` defines the contract and knows no algorithm; each engine
crate implements it and documents its own key and IV lengths, keystream limits
and timing guarantees.

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std` and
reaches the heap only through `tc_stream_cipher`'s default-off `alloc` feature.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every build that uses only this workspace's crates and their `tc_*`
dependencies. A feature that enables a third-party crate, such as the
`rustcrypto` feature of `tc_chacha`, follows that crate's minimum Rust version
instead, and dev-dependencies used only by tests and benchmarks are exempt.
The workspace lock tracks the latest dependency releases, so CI on stable
tests what a user on a current toolchain resolves.

## Workspace checks

```text
cargo test --locked
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, checks the `wasm32-unknown-unknown` and `aarch64-unknown-none`
targets and each crate's dependency set, checks the build that Rust 1.85.0
covers, and verifies the package archives. See
[.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
