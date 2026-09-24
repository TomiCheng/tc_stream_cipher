//! The API contract every engine shares: errors leave state and output
//! alone, chunking and single bytes give the same keystream, and both
//! directions apply it.

mod common;

use common::Engine;
use tc_chacha::{
    ChaCha7539Engine, ChaCha7539PortableEngine, ChaChaEngine, ChaChaPortableEngine,
    XChaCha20Engine, XChaCha20PortableEngine,
};
use tc_stream_cipher::{
    CipherDirection, InitError, KeyWithIvRef, StreamCipher, StreamCipherInit, StreamError,
};

/// Runs the contract on an engine that accepts `key_lengths` and
/// `iv_bytes`-byte IVs and displays `algo_name`.
fn check_contract<E: Engine + 'static>(
    mut engine: E,
    key_lengths: &[usize],
    iv_bytes: usize,
    algo_name: &str,
) {
    let key = [0x11; 32];
    let iv = [0x22; 24];
    let params = KeyWithIvRef::new(&key, &iv[..iv_bytes]);
    let input = [0x5a; 193];

    assert_eq!(engine.to_string(), algo_name);
    let mut untouched = [0x55; 4];
    assert_eq!(
        engine.process_bytes(&[0; 4], &mut untouched),
        Err(StreamError::NotInitialised)
    );
    assert_eq!(engine.return_byte(0), Err(StreamError::NotInitialised));
    assert_eq!(untouched, [0x55; 4]);

    for &length in key_lengths {
        let params = KeyWithIvRef::new(&key[..length], &iv[..iv_bytes]);
        assert_eq!(engine.init(CipherDirection::Encrypt, &params), Ok(()));
    }

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut bulk = [0u8; 193];
    assert_eq!(engine.process_bytes(&input, &mut bulk), Ok(193));

    engine.reset();
    let mut chunked = [0u8; 193];
    engine
        .process_bytes(&input[..13], &mut chunked[..13])
        .unwrap();
    engine
        .process_bytes(&input[13..], &mut chunked[13..])
        .unwrap();
    assert_eq!(chunked, bulk);

    engine.reset();
    let single: Vec<u8> = input
        .iter()
        .map(|&byte| engine.return_byte(byte).unwrap())
        .collect();
    assert_eq!(single, bulk);

    engine.reset();
    let mut longer = [0x55; 200];
    assert_eq!(engine.process_bytes(&input, &mut longer), Ok(193));
    assert_eq!(&longer[..193], &bulk);
    assert_eq!(&longer[193..], &[0x55; 7]);

    engine.reset();
    let mut short = [0x55; 192];
    assert_eq!(
        engine.process_bytes(&input, &mut short),
        Err(StreamError::BufferTooShort)
    );
    assert_eq!(short, [0x55; 192]);

    // A rejected key or IV keeps the previous key, IV and position.
    let mut first = [0u8; 13];
    engine.process_bytes(&input[..13], &mut first).unwrap();
    for length in (0..=33).filter(|length| !key_lengths.contains(length)) {
        let bad = KeyWithIvRef::new(&[0; 33][..length], &iv[..iv_bytes]);
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &bad),
            Err(InitError::InvalidKeyLength(length))
        );
    }
    for length in (0..=25).filter(|&length| length != iv_bytes) {
        let bad = KeyWithIvRef::new(&key, &[0; 25][..length]);
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &bad),
            Err(InitError::InvalidIvLength(length))
        );
    }
    let mut rest = [0u8; 180];
    engine.process_bytes(&input[13..], &mut rest).unwrap();
    assert_eq!(&first, &bulk[..13]);
    assert_eq!(&rest, &bulk[13..]);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; 193];
    engine.process_bytes(&bulk, &mut recovered).unwrap();
    assert_eq!(recovered, input);

    let mut boxed: Box<dyn StreamCipher<Error = StreamError>> = Box::new(engine);
    boxed.reset();
    assert_eq!(boxed.return_byte(input[0]), Ok(bulk[0]));
}

#[test]
fn the_portable_engines_keep_state_on_errors_and_agree_across_chunking_and_directions() {
    check_contract(ChaChaPortableEngine::new(), &[16, 32], 8, "ChaCha20");
    check_contract(ChaCha7539PortableEngine::new(), &[32], 12, "ChaCha7539");
    check_contract(XChaCha20PortableEngine::new(), &[32], 24, "XChaCha20");
}

/// The selecting engines accept exactly what the portable ones do, with or
/// without the `rustcrypto` feature.
#[test]
fn the_selecting_engines_keep_the_portable_contract_under_either_feature_setting() {
    check_contract(ChaChaEngine::new(), &[16, 32], 8, "ChaCha20");
    check_contract(ChaCha7539Engine::new(), &[32], 12, "ChaCha7539");
    check_contract(XChaCha20Engine::new(), &[32], 24, "XChaCha20");
}

/// Switching the key length moves `ChaChaEngine` between backends; each
/// switch must give the same keystream as the portable engine.
#[test]
fn chacha_engine_matches_the_portable_engine_across_backend_switches() {
    let iv = [0x33; 8];
    let input = [0x5a; 150];
    let mut selecting = ChaChaEngine::new();
    for key in [&[0x44; 32][..], &[0x44; 16], &[0x44; 32], &[0x55; 32]] {
        let params = KeyWithIvRef::new(key, &iv);
        let mut portable = ChaChaPortableEngine::new();
        portable.init(CipherDirection::Encrypt, &params).unwrap();
        selecting.init(CipherDirection::Encrypt, &params).unwrap();
        let (mut expected, mut actual) = ([0; 150], [0; 150]);
        portable.process_bytes(&input, &mut expected).unwrap();
        selecting.process_bytes(&input, &mut actual).unwrap();
        assert_eq!(actual, expected, "{}-byte key", key.len());
    }
}

#[cfg(feature = "rustcrypto")]
#[test]
fn the_rustcrypto_engines_keep_the_same_contract() {
    use tc_chacha::{
        ChaCha7539RustCryptoEngine, ChaChaRustCryptoEngine, XChaCha20RustCryptoEngine,
    };

    check_contract(ChaChaRustCryptoEngine::new(), &[32], 8, "ChaCha20");
    check_contract(ChaCha7539RustCryptoEngine::new(), &[32], 12, "ChaCha7539");
    check_contract(XChaCha20RustCryptoEngine::new(), &[32], 24, "XChaCha20");
}

#[test]
fn the_round_count_must_be_positive_and_even_and_shows_in_the_name() {
    for rounds in [0, 1, 7, 21] {
        assert_eq!(
            ChaChaPortableEngine::with_rounds(rounds).err(),
            Some(InitError::InvalidRounds(rounds))
        );
        assert_eq!(
            ChaChaEngine::with_rounds(rounds).err(),
            Some(InitError::InvalidRounds(rounds))
        );
    }
    for rounds in [8, 12, 20] {
        let expected = format!("ChaCha{rounds}");
        let portable = ChaChaPortableEngine::with_rounds(rounds).unwrap();
        assert_eq!(portable.to_string(), expected);
        let selecting = ChaChaEngine::with_rounds(rounds).unwrap();
        assert_eq!(selecting.to_string(), expected);
    }
}
