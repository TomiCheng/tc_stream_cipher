# tc_rc4_family

[![crates.io](https://img.shields.io/crates/v/tc_rc4_family.svg)](https://crates.io/crates/tc_rc4_family)
[![docs.rs](https://docs.rs/tc_rc4_family/badge.svg)](https://docs.rs/tc_rc4_family)
[![CI](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_stream_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

RC4 and the two designs derived from it, VMPC and ISAAC, as stream ciphers,
ported from Bouncy Castle C# and implementing the
[`tc_stream_cipher`](https://crates.io/crates/tc_stream_cipher) traits. All
three keep their state in a table indexed by the state itself, so none is
constant time. RC4 is broken; the crate exists for reading legacy data and
Bouncy Castle compatibility, not for new protocols.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_stream_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), and on RustCrypto's
[`rc4`](https://crates.io/crates/rc4) only with the default-off `rustcrypto`
feature.

Requires Rust 1.85 or later (edition 2024) for the default build. The optional
`rustcrypto` feature follows the minimum Rust version of the `rc4` crate
instead, which is 1.85 for `rc4` 0.2.0.

## Types

- `Rc4Engine` — RC4 on the RustCrypto engine with `rustcrypto`, otherwise on
  the portable engine; a key of 1 to 256 bytes, no IV; variable time.
- `Rc4PortableEngine` — RC4 in portable Rust; variable time.
- `Rc4RustCryptoEngine` (`rustcrypto`) — RC4 through RustCrypto's `rc4`;
  variable time.
- `VmpcEngine` — VMPC: a key and an IV of 16 to 64 bytes each; variable time.
- `VmpcKsa3Engine` — VMPC-KSA3, whose key schedule mixes the key in once more
  after the IV; same lengths; variable time.
- `IsaacEngine` — ISAAC: a key of 0 to 1024 bytes, no IV; variable time.

Another key or IV length returns `InitError::InvalidKeyLength` or
`InitError::InvalidIvLength` and keeps the previous key, IV and position. The
direction is ignored, since both apply the same keystream. `process_bytes`
XORs the input into the start of the output and returns the input length. It
returns `StreamError::NotInitialised` before `init` and
`StreamError::BufferTooShort` for an output shorter than the input; neither
moves the position. None of the ciphers has a keystream limit.

`Display` writes `"RC4"`, `"VMPC"`, `"VMPC-KSA3"` or `"ISAAC"` without
inspecting key material. Each engine has its length constants, implements
`Default` and has `const fn new`.

## Features

- `rustcrypto` (off by default) — adds `Rc4RustCryptoEngine`, which
  `Rc4Engine` then uses; pulls in the `rc4` crate and its minimum Rust
  version. VMPC and ISAAC have no RustCrypto counterpart and are unaffected.

RustCrypto's `rc4` accepts the same 1- to 256-byte keys, so the feature never
changes which keys are accepted. It can neither seek nor be cloned, so
`Rc4RustCryptoEngine` keeps a copy of the key, wiped on drop, and `reset`
reruns the key schedule.

The feature does not make RC4 faster. RustCrypto's key schedule is quicker,
but its keystream measured slower than the portable engine's at every length
in [BENCHES.md](BENCHES.md), so enabling it slows bulk RC4 down; it is there
for those who prefer RustCrypto's implementation.

## Usage

```toml
[dependencies]
tc_rc4_family = "0.1.0"
tc_stream_cipher = "0.1.0"
```

This example encrypts the classic RC4 test message and decrypts it again:

```rust
use tc_rc4_family::Rc4Engine;
use tc_stream_cipher::{CipherDirection, KeyRef, StreamCipher, StreamCipherInit};

let params = KeyRef::new(b"Key");
let mut engine = Rc4Engine::new();
engine
    .init(CipherDirection::Encrypt, &params)
    .expect("RC4 accepts a 3-byte key");
let mut ciphertext = [0u8; 9];
assert_eq!(engine.process_bytes(b"Plaintext", &mut ciphertext), Ok(9));
assert_eq!(ciphertext, [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);

engine.init(CipherDirection::Decrypt, &params).unwrap();
let mut plaintext = [0u8; 9];
assert_eq!(engine.process_bytes(&ciphertext, &mut plaintext), Ok(9));
assert_eq!(&plaintext, b"Plaintext");
```

## Security

No engine is constant time. RC4 and VMPC swap and read permutation entries at
indices taken from the permutation, and ISAAC reads its state at indices taken
from the state, so the memory access pattern depends on secrets and can leak
where a cache is shared with an attacker. RustCrypto's `rc4` works the same
way. RC4's keystream has well-known biases, and RFC 7465 prohibits it in TLS.

The engines wipe their permutation or state, the key, any IV and buffered
keystream on drop; with `rustcrypto`, RustCrypto's `zeroize` feature wipes its
permutation. Wiping does not reach the caller's key buffer or copies left in
registers and on the stack.

These are stream-cipher primitives, not a message-encryption format. They
supply no authentication, and a key (and IV) must never be reused.

## Benchmarks

Key setup and keystream throughput for the portable and RustCrypto RC4
engines, and the commands to reproduce them, are in [BENCHES.md](BENCHES.md).

## Validation

RC4 is tested against Bouncy Castle's vectors, RFC 6229 and the classic
examples; VMPC and VMPC-KSA3 against Bouncy Castle's one-million-byte
checkpoints; and ISAAC against Bouncy Castle's short-key and full-state
vectors. Contract tests cover error state, custom parameter types, the
maximum key lengths, dynamic dispatch, `reset`, agreement between chunked,
bulk and single-byte processing, and both directions. With `rustcrypto`, the
portable and RustCrypto RC4 engines are cross-checked for 1-, 16- and 256-byte
keys across chunking and `reset`.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_rc4_family --locked
cargo test -p tc_rc4_family --locked --features rustcrypto
cargo clippy -p tc_rc4_family --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_rc4_family --check
cargo doc -p tc_rc4_family --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_rc4_family --list --locked
cargo publish -p tc_rc4_family --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
benchmark results, the source, the integration tests and the benchmark. It
must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
