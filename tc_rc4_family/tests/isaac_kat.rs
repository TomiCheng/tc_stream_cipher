use tc_rc4_family::IsaacEngine;
use tc_stream_cipher::{
    CipherDirection, InitError, KeyRef, StreamCipher, StreamCipherInit, StreamError,
};

const MAX_KEY_BYTES: usize = IsaacEngine::MAX_KEY_BYTES;

fn unhex(value: &str) -> Vec<u8> {
    let value: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn keystream(key: &[u8], length: usize) -> Vec<u8> {
    let mut engine = IsaacEngine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(key))
        .unwrap();
    let mut output = vec![0; length];
    engine.process_bytes(&vec![0; length], &mut output).unwrap();
    output
}

#[test]
fn bc_short_key_vectors() {
    assert_eq!(
        keystream(&[0; 4], 64),
        unhex(
            "f650e4c8e448e96d98db2fb4f5fad54f
             433f1afbedec154ad837048746ca4f9a
             5de3743e88381097f1d444eb823cedb6
             6a83e1e04a5f6355c744243325890e2e"
        )
    );
    assert_eq!(
        keystream(&[0xff; 4], 64),
        unhex(
            "de3b3f3c19e0629c1fc8b7836695d523
             e7804edd86ff7ce9b106f52caebae9d9
             72f845d49ce17d7da44e49bae954aac0
             d0b1284b98a88eec1524fb6bc91a16b5"
        )
    );
    assert_eq!(keystream(&[], 64), keystream(&[0; 4], 64));
}

#[test]
fn bc_full_state_vectors() {
    let mut key = [0; MAX_KEY_BYTES];
    for word in key.as_chunks_mut::<4>().0 {
        word[..2].fill(0xff);
    }
    assert_eq!(
        keystream(&key, 64),
        unhex(
            "26c54b1f8c4e3fc582e9e8180f7aba53
             80463dcf58b03cbeda0ecc8ba90ccff8
             5bd50896313d7efed44015faeac6964b
             241a7fb8a2e37127a7cbea0fd7c020f2"
        )
    );

    for word in key.as_chunks_mut::<4>().0 {
        word[..2].fill(0);
        word[2..].fill(0xff);
    }
    assert_eq!(
        keystream(&key, 64),
        unhex(
            "bc31712f2a2f467a5abc737c57ce0f8d
             49d2f775eb850fc8f856daf19310fee2
             5bab40e78403c9ef4ccd971418992faf
             4e85ca643fa6b482f30c4659066158a6"
        )
    );
}

#[test]
fn reset_chunking_and_directions_match() {
    let params = KeyRef::new(b"ISAAC test key");
    let input = vec![0x5a; 1_077];
    let mut engine = IsaacEngine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut bulk = vec![0; input.len()];
    engine.process_bytes(&input, &mut bulk).unwrap();

    engine.reset();
    let mut chunked = vec![0; input.len()];
    engine
        .process_bytes(&input[..13], &mut chunked[..13])
        .unwrap();
    engine
        .process_bytes(&input[13..1023], &mut chunked[13..1023])
        .unwrap();
    engine
        .process_bytes(&input[1023..], &mut chunked[1023..])
        .unwrap();
    assert_eq!(chunked, bulk);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = vec![0; input.len()];
    engine.process_bytes(&bulk, &mut recovered).unwrap();
    assert_eq!(recovered, input);
}

#[test]
fn validates_key_and_runtime_state() {
    let mut engine = IsaacEngine::new();
    assert_eq!(engine.to_string(), "ISAAC");
    assert_eq!(engine.return_byte(0), Err(StreamError::NotInitialised));
    assert_eq!(
        engine.init(
            CipherDirection::Encrypt,
            &KeyRef::new(&[0; MAX_KEY_BYTES + 1]),
        ),
        Err(InitError::InvalidKeyLength(MAX_KEY_BYTES + 1))
    );
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(b"key"))
        .unwrap();
    assert_eq!(
        engine.process_bytes(&[0; 2], &mut [0; 1]),
        Err(StreamError::BufferTooShort)
    );
}
