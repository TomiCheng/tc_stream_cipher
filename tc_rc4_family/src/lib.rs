//! RC4 and the two designs derived from it, VMPC and ISAAC, on the
//! `tc_stream_cipher` traits.
//!
//! All three keep their state in a table indexed by the state itself, so the
//! positions they read and write depend on secrets: none is constant time, and
//! each can leak where a cache is shared. RC4 is broken, and VMPC and ISAAC are
//! rarely used; they are kept for Bouncy Castle compatibility and reading
//! legacy data. Prefer ChaCha for new protocols.
//!
//! With the `rustcrypto` feature, [`Rc4Engine`] runs on RustCrypto's `rc4`.
//! VMPC and ISAAC have no RustCrypto counterpart and are unaffected.
//!
//! ```
//! use tc_rc4_family::Rc4Engine;
//! use tc_stream_cipher::{CipherDirection, KeyRef, StreamCipher, StreamCipherInit};
//!
//! let mut cipher = Rc4Engine::new();
//! cipher.init(CipherDirection::Encrypt, &KeyRef::new(b"Key"))?;
//!
//! let mut output = [0u8; 9];
//! cipher.process_bytes(b"Plaintext", &mut output)?;
//! assert_eq!(output, [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod isaac_engine;
mod rc4_engine;
mod rc4_portable_engine;
#[cfg(feature = "rustcrypto")]
mod rc4_rustcrypto_engine;
mod vmpc_engine;
mod vmpc_ksa3_engine;
mod vmpc_state;

pub use isaac_engine::IsaacEngine;
pub use rc4_engine::Rc4Engine;
pub use rc4_portable_engine::Rc4PortableEngine;
#[cfg(feature = "rustcrypto")]
pub use rc4_rustcrypto_engine::Rc4RustCryptoEngine;
pub use vmpc_engine::VmpcEngine;
pub use vmpc_ksa3_engine::VmpcKsa3Engine;
