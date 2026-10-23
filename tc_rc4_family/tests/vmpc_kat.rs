use tc_rc4_family::{VmpcEngine, VmpcKsa3Engine};
use tc_stream_cipher::{
    CipherDirection, InitError, KeyWithIvRef, StreamCipher, StreamCipherInit, StreamError,
};

const MIN_KEY_BYTES: usize = VmpcKsa3Engine::MIN_KEY_BYTES;
const MAX_KEY_BYTES: usize = VmpcKsa3Engine::MAX_KEY_BYTES;
const MIN_IV_BYTES: usize = VmpcKsa3Engine::MIN_IV_BYTES;
const MAX_IV_BYTES: usize = VmpcKsa3Engine::MAX_IV_BYTES;

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn vector_params() -> (Vec<u8>, Vec<u8>) {
    (
        unhex("9661410AB797D8A9EB767C21172DF6C7"),
        unhex("4B5C2F003E67F39557A8D26F3DA2B155"),
    )
}

fn assert_positions(output: &[u8], expected: &[(usize, u8)]) {
    for &(position, byte) in expected {
        assert_eq!(output[position], byte, "mismatch at position {position}");
    }
}

#[test]
fn vmpc_matches_bc_million_byte_vector() {
    let (key, iv) = vector_params();
    let params = KeyWithIvRef::new(&key, &iv);
    let input = vec![0; 1_000_000];
    let mut output = vec![0; input.len()];
    let mut engine = VmpcEngine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_bytes(&input, &mut output).unwrap();
    assert_positions(
        &output,
        &[
            (0, 0xa8),
            (1, 0x24),
            (2, 0x79),
            (3, 0xf5),
            (252, 0xb8),
            (253, 0xfc),
            (254, 0x66),
            (255, 0xa4),
            (1020, 0xe0),
            (1021, 0x56),
            (1022, 0x40),
            (1023, 0xa5),
            (102_396, 0x81),
            (102_397, 0xca),
            (102_398, 0x49),
            (102_399, 0x9a),
        ],
    );
    engine.reset();
    let mut after_reset = vec![0; input.len()];
    engine.process_bytes(&input, &mut after_reset).unwrap();
    assert_eq!(after_reset, output);
}

#[test]
fn vmpc_ksa3_matches_bc_million_byte_vector() {
    let (key, iv) = vector_params();
    let params = KeyWithIvRef::new(&key, &iv);
    let input = vec![0; 1_000_000];
    let mut output = vec![0; input.len()];
    let mut engine = VmpcKsa3Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    engine.process_bytes(&input, &mut output).unwrap();
    assert_positions(
        &output,
        &[
            (0, 0xb6),
            (1, 0xeb),
            (2, 0xae),
            (3, 0xfe),
            (252, 0x48),
            (253, 0x17),
            (254, 0x24),
            (255, 0x73),
            (1020, 0x1d),
            (1021, 0xae),
            (1022, 0xc3),
            (1023, 0x5a),
            (102_396, 0x1d),
            (102_397, 0xa7),
            (102_398, 0xe1),
            (102_399, 0xdc),
        ],
    );
}

#[test]
fn chunking_single_bytes_and_directions_match() {
    let key = [0x11; 32];
    let iv = [0x22; 48];
    let params = KeyWithIvRef::new(&key, &iv);
    let input = [0x5a; 777];
    let mut engine = VmpcEngine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut bulk = [0; 777];
    engine.process_bytes(&input, &mut bulk).unwrap();

    engine.reset();
    let mut chunked = [0; 777];
    for (source, destination) in input.chunks(63).zip(chunked.chunks_mut(63)) {
        engine.process_bytes(source, destination).unwrap();
    }
    assert_eq!(chunked, bulk);

    engine.reset();
    let single: Vec<_> = input
        .iter()
        .map(|&byte| engine.return_byte(byte).unwrap())
        .collect();
    assert_eq!(single, bulk);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0; 777];
    engine.process_bytes(&bulk, &mut recovered).unwrap();
    assert_eq!(recovered, input);
}

#[test]
fn validates_parameters_and_runtime_state() {
    let mut engine = VmpcKsa3Engine::new();
    assert_eq!(engine.to_string(), "VMPC-KSA3");
    assert_eq!(VmpcEngine::new().to_string(), "VMPC");
    assert_eq!(engine.return_byte(0), Err(StreamError::NotInitialised));
    for length in [MIN_KEY_BYTES - 1, MAX_KEY_BYTES + 1] {
        let key = vec![0; length];
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &KeyWithIvRef::new(&key, &[0; MIN_IV_BYTES]),
            ),
            Err(InitError::InvalidKeyLength(length))
        );
    }
    for length in [MIN_IV_BYTES - 1, MAX_IV_BYTES + 1] {
        let iv = vec![0; length];
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &KeyWithIvRef::new(&[0; MIN_KEY_BYTES], &iv),
            ),
            Err(InitError::InvalidIvLength(length))
        );
    }
}
