# tc_chacha benchmarks

Key setup and keystream throughput for the portable and RustCrypto engines.
The selecting engines only forward to these backends and are not measured
separately. Both backends are constant time, so they are compared under the
same contract. These are performance measurements, not constant-time
verification.

## Running

All 24 cases, portable and RustCrypto (about 8 minutes plus compilation):

```text
cargo bench -p tc_chacha --bench chacha --features rustcrypto
```

Without `--features rustcrypto` only the 12 portable cases run. Criterion
filters follow `--`, for example `-- 'chacha/chacha7539/process'`. To check
that every case runs without measuring:

```text
cargo bench -p tc_chacha --bench chacha --features rustcrypto -- --test
```

Each case warms up for 3 seconds and measures for 15 seconds, with 100
samples.

- **Setup cases** reinitialise an existing engine with a 32-byte key. The
  XChaCha20 figure includes HChaCha20.
- **Process cases** exclude key setup and keep advancing one keystream.

## Recorded results

Measured on 2026-09-24:

- CPU: Intel Core i7-1185G7.
- Toolchain: rustc 1.98.0, `x86_64-pc-windows-msvc`, optimized bench profile.
- RustCrypto chooses its SIMD backend at run time, and this run did not
  record which one it used.
- These are estimates from one local run, not portable guarantees.

Keystream throughput (higher is better):

| Variant | Length | Portable | RustCrypto |
| --- | ---: | ---: | ---: |
| ChaCha20 | 64 B | 408 MiB/s | 675 MiB/s |
| ChaCha20 | 1 KiB | 365 MiB/s | 2.25 GiB/s |
| ChaCha20 | 16 KiB | 391 MiB/s | 2.28 GiB/s |
| ChaCha7539 | 64 B | 397 MiB/s | 693 MiB/s |
| ChaCha7539 | 1 KiB | 375 MiB/s | 2.25 GiB/s |
| ChaCha7539 | 16 KiB | 401 MiB/s | 2.22 GiB/s |
| XChaCha20 | 64 B | 410 MiB/s | 696 MiB/s |
| XChaCha20 | 1 KiB | 424 MiB/s | 2.29 GiB/s |
| XChaCha20 | 16 KiB | 419 MiB/s | 2.29 GiB/s |

Key setup in ns per initialisation (lower is better):

| Variant | Portable | RustCrypto |
| --- | ---: | ---: |
| ChaCha20 | 17.4 | 32.3 |
| ChaCha7539 | 17.6 | 34.2 |
| XChaCha20 | 185.4 | 138.4 |

### Throughput

- RustCrypto is about 5.8 times faster from 1 KiB up, and about 1.7 times
  faster for a single 64-byte block.
- The portable engine stays near 400 MiB/s at every length, because it
  processes one byte at a time. XORing a whole 64-byte block per step would
  be the next thing to try there.
- The three variants share one permutation, so their throughput matches.

### Key setup

- The portable engine sets up ChaCha20 and ChaCha7539 in about half
  RustCrypto's time.
- For XChaCha20, RustCrypto is faster. Its setup is dominated by HChaCha20,
  a full extra permutation.

### Noise

Several cases had 8–15% outliers, and the portable 1 KiB cases had wide
confidence intervals. Repeat under controlled conditions before relying on
differences below about 10%.
