mod common;

use tc_hc::{Hc128Engine, Hc256Engine};
use tc_stream_cipher::{
    CipherDirection, InitError, KeyWithIvRef, StreamCipher, StreamCipherInit, StreamError,
};

use common::unhex;

fn stream128(key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut engine = Hc128Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyWithIvRef::new(key, iv))
        .unwrap();
    let mut output = vec![0; 64];
    engine.process_bytes(&[0; 64], &mut output).unwrap();
    output
}

fn stream256(key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut engine = Hc256Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyWithIvRef::new(key, iv))
        .unwrap();
    let mut output = vec![0; 64];
    engine.process_bytes(&[0; 64], &mut output).unwrap();
    output
}

#[test]
fn hc128_official_vectors() {
    assert_eq!(
        stream128(&[0; 16], &[0; 16]),
        unhex(
            "82001573A003FD3B7FD72FFB0EAF63AA
             C62F12DEB629DCA72785A66268EC758B
             1EDB36900560898178E0AD009ABF1F49
             1330DC1C246E3D6CB264F6900271D59C"
        )
    );
    assert_eq!(
        stream128(
            &unhex("0053A6F94C9FF24598EB3E91E4378ADD"),
            &unhex("0D74DB42A91077DE45AC137AE148AF16"),
        ),
        unhex(
            "2E1ED12A8551C05AF41FF39D8F9DF933
             122B5235D48FC2A6F20037E69BDBBCE8
             05782EFC16C455A4B3FF06142317535E
             F876104C32445138CB26EBC2F88A684C"
        )
    );
}

#[test]
fn hc256_official_vectors() {
    assert_eq!(
        stream256(&[0; 16], &[0; 16]),
        unhex(
            "5B078985D8F6F30D42C5C02FA6B67951
             53F06534801F89F24E74248B720B4818
             CD9227ECEBCF4DBF8DBF6977E4AE14FA
             E8504C7BC8A9F3EA6C0106F5327E6981"
        )
    );
    assert_eq!(
        stream256(
            &unhex("0053A6F94C9FF24598EB3E91E4378ADD 3083D6297CCF2275C81B6EC11467BA0D"),
            &unhex("0D74DB42A91077DE45AC137AE148AF16 7DE44BB21980E74EB51C83EA51B81F86"),
        ),
        unhex(
            "23D9E70A45EB0127884D66D9F6F23C01
             D1F88AFD629270127247256C1FFF91E9
             1A797BD98ADD23AE15BEE6EEA3CEFDBF
             A3ED6D22D9C4F459DB10C40CDF4F4DFF"
        )
    );
}

#[test]
fn hc256_normalises_bc_key_and_iv_lengths() {
    let key16 = unhex("80000000000000000000000000000000");
    let mut key32 = key16.clone();
    key32.extend_from_slice(&[0; 16]);
    let expected16 = unhex(
        "F1B055D7BF34DE7E524D23B5556B743A
         EAF06AE9076FD2F48389039C4B24C38D
         DFC3AC63A148755FB3CF0CB8FB1EDEEA
         63CD484036FFAC3F5F99FC7A10335060",
    );
    assert_eq!(stream256(&key16, &[0; 16]), expected16);
    assert_eq!(stream256(&key16, &[0; 32]), expected16);

    let expected32 = unhex(
        "240146C5EA6C72A8DFC93E54E8811C32
         A85E0BF7291BDDC0DBEAE086D051D5B0
         5CC9DD5C311ED2F7E8484CC477C68BC8
         C5D3F3450553F5327253768E958C0C55",
    );
    assert_eq!(stream256(&key32, &[0; 16]), expected32);
    assert_eq!(stream256(&key32, &[0; 32]), expected32);

    let mut iv48 = [0x24; 48];
    iv48[32..].fill(0xff);
    assert_eq!(
        stream256(&[0x42; 32], &[0x24; 32]),
        stream256(&[0x42; 32], &iv48)
    );
}

#[test]
fn reset_chunking_and_directions_match() {
    let key = [0x11; 16];
    let iv = [0x22; 16];
    let params = KeyWithIvRef::new(&key, &iv);
    let input = [0x5a; 97];
    let mut engine = Hc128Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut bulk = [0; 97];
    engine.process_bytes(&input, &mut bulk).unwrap();
    engine.reset();
    let mut chunked = [0; 97];
    engine
        .process_bytes(&input[..13], &mut chunked[..13])
        .unwrap();
    engine
        .process_bytes(&input[13..], &mut chunked[13..])
        .unwrap();
    assert_eq!(chunked, bulk);
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0; 97];
    engine.process_bytes(&bulk, &mut recovered).unwrap();
    assert_eq!(recovered, input);
}

#[test]
fn validates_parameters_and_runtime_state() {
    let mut hc128 = Hc128Engine::new();
    assert_eq!(hc128.to_string(), "HC-128");
    assert_eq!(hc128.return_byte(0), Err(StreamError::NotInitialised));
    assert_eq!(
        hc128.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; 15], &[0; Hc128Engine::IV_BYTES]),
        ),
        Err(InitError::InvalidKeyLength(15))
    );
    assert_eq!(
        hc128.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; Hc128Engine::KEY_BYTES], &[0; 15]),
        ),
        Err(InitError::InvalidIvLength(15))
    );

    let mut hc256 = Hc256Engine::new();
    assert_eq!(hc256.to_string(), "HC-256");
    assert_eq!(hc256.return_byte(0), Err(StreamError::NotInitialised));
    assert_eq!(
        hc256.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; 15], &[0; Hc256Engine::MIN_IV_BYTES]),
        ),
        Err(InitError::InvalidKeyLength(15))
    );
    assert_eq!(
        hc256.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; 16], &[0; 15]),
        ),
        Err(InitError::InvalidIvLength(15))
    );
}

#[test]
fn a_rejected_init_keeps_the_previous_key_and_position() {
    let params = KeyWithIvRef::new(&[0x11; 16], &[0x22; 16]);
    let mut expected = [0; 40];
    let mut engine = Hc128Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_bytes(&[0; 40], &mut expected).unwrap();

    let mut engine = Hc128Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut first = [0; 13];
    engine.process_bytes(&[0; 13], &mut first).unwrap();
    assert!(
        engine
            .init(
                CipherDirection::Encrypt,
                &KeyWithIvRef::new(&[0; 15], &[0; 16])
            )
            .is_err()
    );
    let mut rest = [0; 27];
    engine.process_bytes(&[0; 27], &mut rest).unwrap();
    assert_eq!([&first[..], &rest[..]].concat(), expected);
}
