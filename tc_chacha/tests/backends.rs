//! Differential checks: each portable engine against its RustCrypto
//! counterpart on pseudorandom keys, IVs, lengths and chunkings.

#![cfg(feature = "rustcrypto")]

mod common;

use common::Engine;
use tc_chacha::{
    ChaCha7539PortableEngine, ChaCha7539RustCryptoEngine, ChaChaPortableEngine,
    ChaChaRustCryptoEngine, XChaCha20PortableEngine, XChaCha20RustCryptoEngine,
};
use tc_stream_cipher::{CipherDirection, KeyWithIvRef};

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.next() as u8)
    }
}

/// Feeds the portable engine in random chunks and RustCrypto in one call.
fn agree<P: Engine, R: Engine, const IV: usize>(portable: fn() -> P, rustcrypto: fn() -> R) {
    let mut random = XorShift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..64 {
        let key: [u8; 32] = random.bytes();
        let iv: [u8; IV] = random.bytes();
        let params = KeyWithIvRef::new(&key, &iv);
        let input: Vec<u8> = (0..random.next() % 400)
            .map(|_| random.next() as u8)
            .collect();

        let mut expected = vec![0; input.len()];
        let mut engine = rustcrypto();
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        engine.process_bytes(&input, &mut expected).unwrap();

        let mut actual = vec![0; input.len()];
        let mut engine = portable();
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        let mut done = 0;
        while done < input.len() {
            let step = (1 + random.next() as usize % 97).min(input.len() - done);
            engine
                .process_bytes(&input[done..done + step], &mut actual[done..done + step])
                .unwrap();
            done += step;
        }
        assert_eq!(actual, expected, "{} bytes", input.len());
    }
}

#[test]
fn the_portable_engines_agree_with_rustcrypto_on_pseudorandom_inputs() {
    agree::<_, _, 8>(ChaChaPortableEngine::new, ChaChaRustCryptoEngine::new);
    agree::<_, _, 12>(
        ChaCha7539PortableEngine::new,
        ChaCha7539RustCryptoEngine::new,
    );
    agree::<_, _, 24>(XChaCha20PortableEngine::new, XChaCha20RustCryptoEngine::new);
}
