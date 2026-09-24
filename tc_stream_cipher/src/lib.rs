//! Shared interfaces and key and IV containers for stream ciphers.
//!
//! This crate defines how to initialize a stream cipher and apply its
//! keystream; it does not implement an encryption algorithm or
//! authentication. Use a concrete engine with these traits, and an
//! authenticated-encryption construction when protecting messages.
//!
//! # Using an engine
//!
//! Supply the key through [`KeyParams`] and, for ciphers that take one, the
//! IV (nonce) through [`IvParams`], select a [`CipherDirection`], and call
//! [`StreamCipherInit::init`]. After successful initialization,
//! [`StreamCipher::process_bytes`] transforms a slice and
//! [`StreamCipher::return_byte`] a single byte, both advancing the keystream,
//! and [`StreamCipher::reset`] returns to its start. Supported key and IV
//! lengths, round counts, keystream limits, timing guarantees and state after
//! a rejected initialization are defined by the concrete engine.
//!
//! # Implementing an engine
//!
//! An engine implements [`StreamCipherInit`] for the parameters it accepts and
//! [`StreamCipher`] for processing. The toy engine below repeats a four-byte
//! key XORed with a four-byte IV as its keystream; it shows the contract and
//! is not a cipher.
//!
//! ```
//! use tc_stream_cipher::{
//!     CipherDirection, InitError, IvParams, KeyParams, KeyWithIvFixed, KeyWithIvRef,
//!     StreamCipher, StreamCipherInit, StreamError,
//! };
//!
//! struct Xor4 {
//!     pad: Option<[u8; 4]>,
//!     position: usize,
//! }
//!
//! impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Xor4 {
//!     type Error = InitError;
//!
//!     fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
//!         let (key, iv) = (params.key(), params.iv());
//!         let key: [u8; 4] = key.try_into().map_err(|_| InitError::InvalidKeyLength(key.len()))?;
//!         let iv: [u8; 4] = iv.try_into().map_err(|_| InitError::InvalidIvLength(iv.len()))?;
//!         self.pad = Some(core::array::from_fn(|index| key[index] ^ iv[index]));
//!         self.position = 0;
//!         Ok(())
//!     }
//! }
//!
//! impl StreamCipher for Xor4 {
//!     type Error = StreamError;
//!
//!     fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
//!         let mut output = [0];
//!         self.process_bytes(&[input], &mut output)?;
//!         Ok(output[0])
//!     }
//!
//!     fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
//!         let pad = self.pad.ok_or(StreamError::NotInitialised)?;
//!         let output = output.get_mut(..input.len()).ok_or(StreamError::BufferTooShort)?;
//!         for (out, byte) in output.iter_mut().zip(input) {
//!             *out = byte ^ pad[self.position % 4];
//!             self.position += 1;
//!         }
//!         Ok(input.len())
//!     }
//!
//!     fn reset(&mut self) {
//!         self.position = 0;
//!     }
//! }
//!
//! let mut engine = Xor4 { pad: None, position: 0 };
//! assert_eq!(engine.return_byte(0), Err(StreamError::NotInitialised));
//!
//! let params = KeyWithIvFixed::new([0xf0; 4], [0x0f, 0x0f, 0x0f, 0x0e]);
//! engine.init(CipherDirection::Encrypt, &params)?;
//! let mut ciphertext = [0; 5];
//! assert_eq!(engine.process_bytes(b"hello", &mut ciphertext)?, 5);
//! assert_eq!(ciphertext, [0x97, 0x9a, 0x93, 0x92, 0x90]);
//!
//! engine.init(CipherDirection::Decrypt, &params)?;
//! let mut plaintext = [0; 5];
//! engine.process_bytes(&ciphertext, &mut plaintext)?;
//! assert_eq!(&plaintext, b"hello");
//!
//! let short_iv = [0; 3];
//! assert_eq!(
//!     engine.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&[0; 4], &short_iv)),
//!     Err(InitError::InvalidIvLength(3))
//! );
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Choosing parameter storage
//!
//! - [`KeyRef`] and [`KeyWithIvRef`] borrow existing bytes without copying or
//!   wiping them.
//! - [`KeyFixed`] and [`KeyWithIvFixed`] own fixed-size arrays and wipe them
//!   on drop.
//! - `KeyOwned` and `KeyWithIvOwned`, available with the `alloc` feature, take
//!   ownership of byte vectors and wipe them on drop.
//!
//! The key-only containers serve ciphers that take no IV, such as RC4. None of
//! the containers validates algorithm-specific lengths. Wiping an owned
//! container does not erase caller-held copies, engine state or every
//! temporary copy. Callers must manage those lifetimes separately.
//!
//! # Features
//!
//! The crate is `no_std` and requires no allocator by default. Enable `alloc`
//! for `KeyOwned` and `KeyWithIvOwned`; this does not require the standard
//! library.
//!
//! [`InitError`] and [`StreamError`] are reusable error types. The traits use
//! associated error types so an engine may expose more specific failures.
//!
#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod cipher_direction;
mod init_error;
mod params;
mod stream_error;
mod traits;

pub use cipher_direction::CipherDirection;
pub use init_error::InitError;
pub use params::{KeyFixed, KeyRef, KeyWithIvFixed, KeyWithIvRef};
#[cfg(feature = "alloc")]
pub use params::{KeyOwned, KeyWithIvOwned};
pub use stream_error::StreamError;
pub use traits::{IvParams, KeyParams, StreamCipher, StreamCipherInit};
