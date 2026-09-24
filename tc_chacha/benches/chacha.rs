//! ChaCha key setup and keystream throughput for the portable and RustCrypto
//! engines.
//!
//! Run `cargo bench -p tc_chacha --bench chacha`, or add
//! `--features rustcrypto` to include RustCrypto. Optional Criterion filters
//! follow `--`, for example `-- 'chacha/chacha7539/process'`.
//!
//! Setup benchmarks reinitialise an existing engine with a 32-byte key; the
//! XChaCha20 figure includes HChaCha20. Process benchmarks exclude key setup,
//! keep advancing one keystream, and report bytes per second. The selecting
//! engines only forward to these backends and are not measured separately.
//! Both backends are constant time, so the comparison is between equal
//! contracts. These are performance measurements, not constant-time
//! verification.

use std::{hint::black_box, time::Duration};

use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use tc_chacha::{ChaCha7539PortableEngine, ChaChaPortableEngine, XChaCha20PortableEngine};
#[cfg(feature = "rustcrypto")]
use tc_chacha::{ChaCha7539RustCryptoEngine, ChaChaRustCryptoEngine, XChaCha20RustCryptoEngine};
use tc_stream_cipher::{
    CipherDirection, InitError, KeyWithIvRef, StreamCipher, StreamCipherInit, StreamError,
};

/// Message sizes for the process benchmarks: one block, a packet, a buffer.
const SIZES: [usize; 3] = [64, 1024, 16 * 1024];

trait Engine:
    StreamCipher<Error = StreamError> + for<'a> StreamCipherInit<KeyWithIvRef<'a>, Error = InitError>
{
}

impl<E> Engine for E where
    E: StreamCipher<Error = StreamError>
        + for<'a> StreamCipherInit<KeyWithIvRef<'a>, Error = InitError>
{
}

const KEY: [u8; 32] = [0x42; 32];
const IV: [u8; 24] = [0x24; 24];

fn add_setup<E: Engine>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    backend: &str,
    iv_bytes: usize,
    create: fn() -> E,
) {
    let params = KeyWithIvRef::new(&KEY, &IV[..iv_bytes]);
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
    iv_bytes: usize,
    create: fn() -> E,
) {
    for size in SIZES {
        let mut engine = create();
        let params = KeyWithIvRef::new(&KEY, &IV[..iv_bytes]);
        engine.init(CipherDirection::Encrypt, &params).unwrap();
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

/// Registers the setup and process groups for one variant; `$rustcrypto`
/// only exists with the feature.
macro_rules! bench_variant {
    ($c:expr, $name:literal, $portable:ident, $rustcrypto:ident) => {{
        let iv_bytes = $portable::IV_BYTES;

        let mut group = $c.benchmark_group(concat!("chacha/", $name, "/init"));
        group.throughput(Throughput::Elements(1));
        add_setup(&mut group, "portable", iv_bytes, $portable::new);
        #[cfg(feature = "rustcrypto")]
        add_setup(&mut group, "rustcrypto", iv_bytes, $rustcrypto::new);
        group.finish();

        let mut group = $c.benchmark_group(concat!("chacha/", $name, "/process"));
        add_process(&mut group, "portable", iv_bytes, $portable::new);
        #[cfg(feature = "rustcrypto")]
        add_process(&mut group, "rustcrypto", iv_bytes, $rustcrypto::new);
        group.finish();
    }};
}

fn benchmarks(c: &mut Criterion) {
    bench_variant!(c, "chacha20", ChaChaPortableEngine, ChaChaRustCryptoEngine);
    bench_variant!(
        c,
        "chacha7539",
        ChaCha7539PortableEngine,
        ChaCha7539RustCryptoEngine
    );
    bench_variant!(
        c,
        "xchacha20",
        XChaCha20PortableEngine,
        XChaCha20RustCryptoEngine
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15));
    targets = benchmarks
}
criterion_main!(benches);
