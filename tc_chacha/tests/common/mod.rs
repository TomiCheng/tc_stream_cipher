//! Helpers shared by the integration tests.

// Each test file uses a different subset.
#![allow(dead_code)]

use tc_stream_cipher::{
    CipherDirection, InitError, KeyWithIvRef, StreamCipher, StreamCipherInit, StreamError,
};

/// Everything the tests need from an engine.
pub trait Engine:
    core::fmt::Display
    + StreamCipher<Error = StreamError>
    + for<'a> StreamCipherInit<KeyWithIvRef<'a>, Error = InitError>
{
}

impl<E> Engine for E where
    E: core::fmt::Display
        + StreamCipher<Error = StreamError>
        + for<'a> StreamCipherInit<KeyWithIvRef<'a>, Error = InitError>
{
}

/// Decodes hex, ignoring whitespace.
pub fn unhex(value: &str) -> Vec<u8> {
    let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

/// The first `length` keystream bytes for `key` and `iv`.
pub fn keystream<E: Engine>(mut engine: E, key: &[u8], iv: &[u8], length: usize) -> Vec<u8> {
    engine
        .init(CipherDirection::Encrypt, &KeyWithIvRef::new(key, iv))
        .unwrap();
    let mut output = vec![0u8; length];
    engine
        .process_bytes(&vec![0u8; length], &mut output)
        .unwrap();
    output
}
