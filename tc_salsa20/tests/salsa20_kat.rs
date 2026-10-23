mod common;

use tc_salsa20::{Salsa20Engine, Xsalsa20Engine};
use tc_stream_cipher::{
    CipherDirection, InitError, KeyWithIvRef, StreamCipher, StreamCipherInit, StreamError,
};

use common::unhex;

fn keystream(rounds: usize, key: &[u8], iv: &[u8], length: usize) -> Vec<u8> {
    let mut engine = Salsa20Engine::with_rounds(rounds).unwrap();
    engine
        .init(CipherDirection::Encrypt, &KeyWithIvRef::new(key, iv))
        .unwrap();
    let mut output = vec![0; length];
    engine.process_bytes(&vec![0; length], &mut output).unwrap();
    output
}

#[test]
fn salsa20_bc_vectors() {
    let key = unhex("80000000000000000000000000000000");
    let stream = keystream(20, &key, &[0; 8], 512);
    assert_eq!(
        &stream[..64],
        unhex(
            "4DFA5E481DA23EA09A31022050859936
             DA52FCEE218005164F267CB65F5CFD7F
             2B4F97E0FF16924A52DF269515110A07
             F9E460BC65EF95DA58F740B7D1DBB0AA"
        )
    );
    assert_eq!(
        &stream[448..512],
        unhex(
            "B375703739DACED4DD4059FD71C3C47F
             C2F9939670FAD4A46066ADCC6A564578
             3308B90FFB72BE04A6B147CBE38CC0C3
             B9267C296A92A7C69873F9F263BE9703"
        )
    );
    assert_eq!(
        keystream(12, &key, &[0; 8], 64),
        unhex(
            "FC207DBFC76C5E1774961E7A5AAD0906
             9B2225AC1CE0FE7A0CE77003E7E5BDF8
             B31AF821000813E6C56B8C1771D6EE70
             39B2FBD0A68E8AD70A3944B677937897"
        )
    );
    assert_eq!(
        keystream(8, &key, &[0; 8], 64),
        unhex(
            "A9C9F888AB552A2D1BBFF9F36BEBEB33
             7A8B4B107C75B63BAE26CB9A235BBA9D
             784F38BEFC3ADF4CD3E266687EA7B9F0
             9BA650AE81EAC6063AE31FF12218DDC5"
        )
    );
}

#[test]
fn salsa20_256_bit_key_counter_vector() {
    let key = unhex("0053A6F94C9FF24598EB3E91E4378ADD 3083D6297CCF2275C81B6EC11467BA0D");
    let iv = unhex("0D74DB42A91077DE");
    let stream = keystream(20, &key, &iv, 65_600);
    assert_eq!(
        &stream[..64],
        unhex(
            "F5FAD53F79F9DF58C4AEA0D0ED9A9601
             F278112CA7180D565B420A48019670EA
             F24CE493A86263F677B46ACE1924773D
             2BB25571E1AA8593758FC382B1280B71"
        )
    );
    assert_eq!(
        &stream[65_536..],
        unhex(
            "81582C65D7562B80AEC2F1A673A9D01C
             9F892A23D4919F6AB47B9154E08E699B
             4117D7C666477B60F8391481682F5D95
             D96623DBC489D88DAA6956B9F0646B6E"
        )
    );
}

#[test]
fn xsalsa20_bc_vectors() {
    let key = unhex("d5c7f6797b7e7e9c1d7fd2610b2abf2b c5a7885fb3ff78092fb3abe8986d35e2");
    let iv = unhex("744e17312b27969d826444640e9c4a37 8ae334f185369c95");
    let plaintext = unhex(
        "7758298c628eb3a4b6963c5445ef6697
         1222be5d1a4ad839715d1188071739b7
         7cc6e05d5410f963a64167629757",
    );
    let expected = unhex(
        "27b8cfe81416a76301fd1eec6a4d9967
         5069b2da2776c360db1bdfea7c0aa613
         913e10f7a60fec04d11e65f2d64e",
    );
    let mut engine = Xsalsa20Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
        .unwrap();
    let mut output = vec![0; plaintext.len()];
    engine.process_bytes(&plaintext, &mut output).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn reset_chunking_single_bytes_and_directions_match() {
    let key = [0x11; 32];
    let iv = [0x22; 8];
    let params = KeyWithIvRef::new(&key, &iv);
    let input = [0x5a; 193];
    let mut engine = Salsa20Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut bulk = [0; 193];
    engine.process_bytes(&input, &mut bulk).unwrap();

    engine.reset();
    let mut chunked = [0; 193];
    engine
        .process_bytes(&input[..13], &mut chunked[..13])
        .unwrap();
    engine
        .process_bytes(&input[13..], &mut chunked[13..])
        .unwrap();
    assert_eq!(chunked, bulk);

    engine.reset();
    let single: Vec<_> = input
        .iter()
        .map(|&byte| engine.return_byte(byte).unwrap())
        .collect();
    assert_eq!(single, bulk);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0; 193];
    engine.process_bytes(&bulk, &mut recovered).unwrap();
    assert_eq!(recovered, input);
}

#[test]
fn validates_configuration_and_runtime_state() {
    assert_eq!(
        Salsa20Engine::with_rounds(0).err(),
        Some(InitError::InvalidRounds(0))
    );
    assert_eq!(
        Salsa20Engine::with_rounds(7).err(),
        Some(InitError::InvalidRounds(7))
    );
    let mut engine = Salsa20Engine::new();
    assert_eq!(engine.to_string(), "Salsa20");
    assert_eq!(
        Salsa20Engine::with_rounds(12).unwrap().to_string(),
        "Salsa20/12"
    );
    assert_eq!(engine.return_byte(0), Err(StreamError::NotInitialised));
    assert_eq!(
        engine.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; 15], &[0; 8]),
        ),
        Err(InitError::InvalidKeyLength(15))
    );
    assert_eq!(
        engine.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; 16], &[0; 7]),
        ),
        Err(InitError::InvalidIvLength(7))
    );

    let mut extended = Xsalsa20Engine::new();
    assert_eq!(extended.to_string(), "XSalsa20");
    assert_eq!(
        extended.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; 16], &[0; Xsalsa20Engine::IV_BYTES]),
        ),
        Err(InitError::InvalidKeyLength(16))
    );
}

#[test]
fn a_rejected_init_keeps_the_previous_key_and_position() {
    let params = KeyWithIvRef::new(&[0x11; 32], &[0x22; 8]);
    let mut expected = [0; 100];
    let mut engine = Salsa20Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_bytes(&[0; 100], &mut expected).unwrap();

    let mut engine = Salsa20Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut first = [0; 70];
    engine.process_bytes(&[0; 70], &mut first).unwrap();
    assert!(
        engine
            .init(
                CipherDirection::Encrypt,
                &KeyWithIvRef::new(&[0; 32], &[0; 7])
            )
            .is_err()
    );
    let mut rest = [0; 30];
    engine.process_bytes(&[0; 30], &mut rest).unwrap();
    assert_eq!([&first[..], &rest[..]].concat(), expected);
}

/// With `rustcrypto`, both backends give the same keystream for a key and IV,
/// across chunking and reset.
#[cfg(feature = "rustcrypto")]
#[test]
fn the_rustcrypto_and_portable_backends_agree() {
    use tc_salsa20::{
        Salsa20PortableEngine, Salsa20RustCryptoEngine, Xsalsa20PortableEngine,
        Xsalsa20RustCryptoEngine,
    };

    fn stream<
        E: StreamCipher<Error = StreamError>
            + StreamCipherInit<KeyWithIvRef<'static>, Error = InitError>,
    >(
        mut engine: E,
        iv: &'static [u8],
    ) -> Vec<u8> {
        static KEY: [u8; 32] = [0x6b; 32];
        engine
            .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&KEY, iv))
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

    static IV8: [u8; 8] = [0x31; 8];
    static IV24: [u8; 24] = [0x47; 24];
    assert_eq!(
        stream(Salsa20RustCryptoEngine::new(), &IV8),
        stream(Salsa20PortableEngine::new(), &IV8)
    );
    assert_eq!(
        stream(Xsalsa20RustCryptoEngine::new(), &IV24),
        stream(Xsalsa20PortableEngine::new(), &IV24)
    );
}
