# tc_rc4_family benchmarks

RC4 key setup and keystream throughput for the portable and RustCrypto
engines. `Rc4Engine` only forwards to one of these backends and is not
measured separately. Both backends index tables with secret state and are
variable time, so they are compared under the same contract. These are
performance measurements, not timing verification. VMPC and ISAAC have no
RustCrypto counterpart and are not benchmarked.

## Running

All 8 cases, portable and RustCrypto (about 3 minutes plus compilation):

```text
cargo bench -p tc_rc4_family --bench rc4 --features rustcrypto
```

Without `--features rustcrypto` only the 4 portable cases run. Criterion
filters follow `--`, for example `-- 'rc4/process'`. To check that every case
runs without measuring:

```text
cargo bench -p tc_rc4_family --bench rc4 --features rustcrypto -- --test
```

Each case warms up for 3 seconds and measures for 15 seconds, with 100
samples. Run on mains power: a laptop on battery throttles its CPU and skews
the figures.

- **Setup cases** reinitialise an existing engine with a 16-byte key.
- **Process cases** exclude key setup and keep advancing one keystream, at 64
  bytes, 1 KiB and 16 KiB.

## Recorded results

Measured on 2026-10-24:

- CPU: Intel Core i7-1185G7, on mains power.
- Toolchain: rustc 1.98.0, `x86_64-pc-windows-msvc`, optimized bench profile.
- The portable 16 KiB case was disturbed in the full run (its interval spanned
  73 to 796 µs) and was measured again on its own; the table shows the rerun.
- These are estimates from one local run, not portable guarantees.

Keystream throughput (higher is better):

| Length | Portable | RustCrypto |
| ---: | ---: | ---: |
| 64 B | 365 MiB/s | 220 MiB/s |
| 1 KiB | 377 MiB/s | 325 MiB/s |
| 16 KiB | 359 MiB/s | 324 MiB/s |

Key setup in µs per initialisation with a 16-byte key (lower is better):

| Portable | RustCrypto |
| ---: | ---: |
| 1.84 | 0.99 |

RustCrypto's key schedule is faster, but its keystream is slower than the
portable engine's at every measured length.
