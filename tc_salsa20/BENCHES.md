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

Not measured yet.
