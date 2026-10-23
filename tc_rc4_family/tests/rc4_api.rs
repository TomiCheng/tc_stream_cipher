use tc_rc4_family::Rc4Engine;
use tc_stream_cipher::{
    CipherDirection, InitError, KeyParams, KeyRef, StreamCipher, StreamCipherInit, StreamError,
};

#[test]
fn displays_the_algorithm_name() {
    assert_eq!(Rc4Engine::new().to_string(), "RC4");
}

#[test]
fn accepts_custom_parameter_implementations() {
    struct Custom<'a>(&'a [u8]);

    impl KeyParams for Custom<'_> {
        fn key(&self) -> &[u8] {
            self.0
        }
    }

    assert!(
        Rc4Engine::new()
            .init(CipherDirection::Encrypt, &Custom(b"Key"))
            .is_ok()
    );
}

#[test]
fn validates_state_key_length_and_output() {
    let mut engine = Rc4Engine::new();
    assert_eq!(engine.return_byte(0), Err(StreamError::NotInitialised));
    assert_eq!(
        engine.process_bytes(&[0; 1], &mut [0; 1]),
        Err(StreamError::NotInitialised)
    );

    for length in [0, Rc4Engine::MAX_KEY_BYTES + 1] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }

    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(b"Key"))
        .unwrap();
    assert_eq!(
        engine.process_bytes(&[0; 2], &mut [0; 1]),
        Err(StreamError::BufferTooShort)
    );
}

#[test]
fn accepts_maximum_key_length() {
    let key = [0xa5; Rc4Engine::MAX_KEY_BYTES];
    assert!(
        Rc4Engine::new()
            .init(CipherDirection::Encrypt, &KeyRef::new(&key))
            .is_ok()
    );
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let mut engine = Rc4Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(b"Key"))
        .unwrap();

    let mut cipher: Box<dyn StreamCipher<Error = StreamError>> = Box::new(engine);
    let mut output = [0u8; 9];
    assert_eq!(cipher.process_bytes(b"Plaintext", &mut output), Ok(9));
    assert_eq!(
        output,
        [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
    );
}

/// With `rustcrypto`, both backends give the same keystream for a key, across
/// chunking and reset.
#[cfg(feature = "rustcrypto")]
#[test]
fn the_rustcrypto_and_portable_backends_agree() {
    use tc_rc4_family::{Rc4PortableEngine, Rc4RustCryptoEngine};

    fn stream<
        E: StreamCipher<Error = StreamError> + for<'a> StreamCipherInit<KeyRef<'a>, Error = InitError>,
    >(
        mut engine: E,
        key: &[u8],
    ) -> Vec<u8> {
        engine
            .init(CipherDirection::Encrypt, &KeyRef::new(key))
            .unwrap();
        let mut output = vec![0; 1000];
        engine.process_bytes(&[0; 333], &mut output[..333]).unwrap();
        engine.process_bytes(&[0; 667], &mut output[333..]).unwrap();
        engine.reset();
        let mut again = vec![0; 1000];
        engine.process_bytes(&[0; 1000], &mut again).unwrap();
        assert_eq!(again, output);
        output
    }

    for key in [&[0x01][..], &[0x6b; 16], &[0xa5; 256]] {
        assert_eq!(
            stream(Rc4RustCryptoEngine::new(), key),
            stream(Rc4PortableEngine::new(), key)
        );
    }
    let mut engine = Rc4RustCryptoEngine::new();
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &KeyRef::new(&[])),
        Err(InitError::InvalidKeyLength(0))
    );
    assert_eq!(engine.return_byte(0), Err(StreamError::NotInitialised));
}
