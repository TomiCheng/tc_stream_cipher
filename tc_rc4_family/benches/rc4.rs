//! RC4 key setup and keystream throughput for the portable and RustCrypto
//! engines.
//!
//! Run `cargo bench -p tc_rc4_family --bench rc4`, or add
//! `--features rustcrypto` to include RustCrypto. Optional Criterion filters
//! follow `--`, for example `-- 'rc4/process'`.
//!
//! Setup benchmarks reinitialise an existing engine with a 16-byte key.
//! Process benchmarks exclude key setup, keep advancing one keystream, and
//! report bytes per second. Both backends index tables with secret state and
//! are variable time, so they are compared under the same contract. These are
//! performance measurements, not timing verification.

use std::{hint::black_box, time::Duration};

use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use tc_rc4_family::Rc4PortableEngine;
#[cfg(feature = "rustcrypto")]
use tc_rc4_family::Rc4RustCryptoEngine;
use tc_stream_cipher::{
    CipherDirection, InitError, KeyRef, StreamCipher, StreamCipherInit, StreamError,
};

/// Message sizes for the process benchmarks: a small packet, a packet, a
/// buffer.
const SIZES: [usize; 3] = [64, 1024, 16 * 1024];

const KEY: [u8; 16] = [0x42; 16];

trait Engine:
    StreamCipher<Error = StreamError> + for<'a> StreamCipherInit<KeyRef<'a>, Error = InitError>
{
}

impl<E> Engine for E where
    E: StreamCipher<Error = StreamError> + for<'a> StreamCipherInit<KeyRef<'a>, Error = InitError>
{
}

fn add_setup<E: Engine>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    backend: &str,
    create: fn() -> E,
) {
    let params = KeyRef::new(&KEY);
    let mut engine = create();
    group.bench_function(backend, |b| {
        b.iter(|| {
            engine
                .init(CipherDirection::Encrypt, black_box(&params))
                .unwrap();
            black_box(&mut engine);
        });
    });
}

fn add_process<E: Engine>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    backend: &str,
    create: fn() -> E,
) {
    for size in SIZES {
        let mut engine = create();
        engine
            .init(CipherDirection::Encrypt, &KeyRef::new(&KEY))
            .unwrap();
        let input = vec![0x5a; size];
        let mut output = vec![0; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new(backend, size), |b| {
            b.iter(|| {
                let written = engine
                    .process_bytes(black_box(&input), black_box(&mut output))
                    .unwrap();
                black_box(written);
                black_box(&output);
            });
        });
    }
}

fn benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("rc4/init");
    group.throughput(Throughput::Elements(1));
    add_setup(&mut group, "portable", Rc4PortableEngine::new);
    #[cfg(feature = "rustcrypto")]
    add_setup(&mut group, "rustcrypto", Rc4RustCryptoEngine::new);
    group.finish();

    let mut group = c.benchmark_group("rc4/process");
    add_process(&mut group, "portable", Rc4PortableEngine::new);
    #[cfg(feature = "rustcrypto")]
    add_process(&mut group, "rustcrypto", Rc4RustCryptoEngine::new);
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15));
    targets = benchmarks
}
criterion_main!(benches);
