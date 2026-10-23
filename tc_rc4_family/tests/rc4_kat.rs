//! RC4 vectors from Bouncy Castle, RFC 6229, and the classic examples.

mod common;

use tc_rc4_family::Rc4Engine;
use tc_stream_cipher::{CipherDirection, KeyRef, StreamCipher, StreamCipherInit};

use common::unhex;

fn crypt(direction: CipherDirection, key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut engine = Rc4Engine::new();
    engine.init(direction, &KeyRef::new(key)).unwrap();
    let mut output = vec![0u8; input.len()];
    assert_eq!(
        engine.process_bytes(input, &mut output).unwrap(),
        input.len()
    );
    output
}

#[test]
fn bouncy_castle_vectors() {
    let key = unhex("0123456789ABCDEF");
    for (plaintext, ciphertext) in [
        ("4e6f772069732074", "3afbb5c77938280d"),
        ("68652074696d6520", "1cf1e29379266d59"),
        ("666f7220616c6c20", "12fbb0c771276459"),
    ] {
        assert_eq!(
            crypt(CipherDirection::Encrypt, &key, &unhex(plaintext)),
            unhex(ciphertext)
        );
    }
}

#[test]
fn classic_vectors() {
    for (key, plaintext, ciphertext) in [
        (&b"Key"[..], &b"Plaintext"[..], "BBF316E8D940AF0AD3"),
        (&b"Wiki"[..], &b"pedia"[..], "1021BF0420"),
        (
            &b"Secret"[..],
            &b"Attack at dawn"[..],
            "45A01F645FC35B383552544B9BF5",
        ),
    ] {
        assert_eq!(
            crypt(CipherDirection::Encrypt, key, plaintext),
            unhex(ciphertext)
        );
    }
}

#[test]
fn rfc_6229_vectors() {
    assert_eq!(
        crypt(CipherDirection::Encrypt, &unhex("0102030405"), &[0u8; 32]),
        unhex("B2396305F03DC027CCC3524A0A1118A86982944F18FC82D589C403A47A0D0919")
    );
    assert_eq!(
        crypt(
            CipherDirection::Encrypt,
            &unhex("0102030405060708090A0B0C0D0E0F10"),
            &[0u8; 16]
        ),
        unhex("9AC7CC9A609D1EF7B2932899CDE41B97")
    );
}

#[test]
fn decrypt_direction_round_trips() {
    let key = b"Secret";
    let plaintext = b"Attack at dawn";
    let ciphertext = crypt(CipherDirection::Encrypt, key, plaintext);
    assert_eq!(crypt(CipherDirection::Decrypt, key, &ciphertext), plaintext);
}

#[test]
fn reset_restarts_the_keystream() {
    let mut engine = Rc4Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(b"Key"))
        .unwrap();

    let mut first = [0u8; 9];
    engine.process_bytes(b"Plaintext", &mut first).unwrap();
    engine.reset();
    let mut second = [0u8; 9];
    engine.process_bytes(b"Plaintext", &mut second).unwrap();
    assert_eq!(first, second);
}

#[test]
fn return_byte_matches_bulk_processing() {
    let input = b"Plaintext and more";
    let expected = crypt(CipherDirection::Encrypt, b"Key", input);

    let mut engine = Rc4Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(b"Key"))
        .unwrap();
    let actual: Vec<u8> = input
        .iter()
        .map(|&byte| engine.return_byte(byte).unwrap())
        .collect();
    assert_eq!(actual, expected);
}
