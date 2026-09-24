//! Shared cipher transformation direction.

/// The transformation direction selected during cipher initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherDirection {
    /// Transform plaintext into ciphertext.
    Encrypt,
    /// Transform ciphertext into plaintext.
    Decrypt,
}
