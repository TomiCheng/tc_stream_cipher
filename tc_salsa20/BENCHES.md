# tc_salsa20 benchmarks

Key setup and keystream throughput for the portable and RustCrypto engines.
The selecting engines only forward to these backends and are not measured
separately. Both backends are constant time, so they are compared under the
same contract. These are performance measurements, not constant-time
verification.

## Running

All 16 cases, portable and RustCrypto (about 5 minutes plus compilation):

```text
cargo bench -p tc_salsa20 --bench salsa20 --features rustcrypto
```

Without `--features rustcrypto` only the 8 portable cases run. Criterion
filters follow `--`, for example `-- 'salsa20/salsa20/process'`. To check that
every case runs without measuring:

```text
cargo bench -p tc_salsa20 --bench salsa20 --features rustcrypto -- --test
```

Each case warms up for 3 seconds and measures for 15 seconds, with 100
samples. Run on mains power: a laptop on battery throttles its CPU and skews
the figures.

- **Setup cases** reinitialise an existing engine with a 32-byte key. The
  XSalsa20 figure includes HSalsa20.
- **Process cases** exclude key setup and keep advancing one keystream, at 64
  bytes, 1 KiB and 16 KiB.

## Recorded results

Measured on 2026-10-24:

- CPU: Intel Core i7-1185G7, on mains power.
- Toolchain: rustc 1.98.0, `x86_64-pc-windows-msvc`, optimized bench profile.
- RustCrypto chooses its backend at run time, and this run did not record
  which one it used.
- These are estimates from one local run, not portable guarantees.

Keystream throughput (higher is better):

| Variant | Length | Portable | RustCrypto |
| --- | ---: | ---: | ---: |
| Salsa20 | 64 B | 328 MiB/s | 461 MiB/s |
| Salsa20 | 1 KiB | 333 MiB/s | 560 MiB/s |
| Salsa20 | 16 KiB | 328 MiB/s | 564 MiB/s |
| XSalsa20 | 64 B | 366 MiB/s | 569 MiB/s |
| XSalsa20 | 1 KiB | 374 MiB/s | 627 MiB/s |
| XSalsa20 | 16 KiB | 371 MiB/s | 634 MiB/s |

Key setup in ns per initialisation (lower is better):

| Variant | Portable | RustCrypto |
| --- | ---: | ---: |
| Salsa20 | 21.9 | 35.0 |
| XSalsa20 | 148.9 | 130.5 |

RustCrypto's keystream runs at about 1.7 times the portable engine's on long
messages, so the selecting engines use it wherever it covers the request. The
portable Salsa20 key setup is faster, but setup is paid once per key and IV.
