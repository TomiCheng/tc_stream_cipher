//! Cipher-initialization error type.

use core::fmt;

/// Failures common to cipher initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitError {
    /// The supplied key length was invalid, in bytes.
    InvalidKeyLength(usize),
    /// The supplied initialization-vector length was invalid, in bytes.
    InvalidIvLength(usize),
    /// The supplied round count was invalid.
    InvalidRounds(usize),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(bytes) => {
                write!(f, "invalid cipher key length: {bytes} bytes")
            }
            Self::InvalidIvLength(bytes) => {
                write!(f, "invalid cipher IV length: {bytes} bytes")
            }
            Self::InvalidRounds(rounds) => {
                write!(f, "invalid cipher round count: {rounds}")
            }
        }
    }
}

impl core::error::Error for InitError {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::InitError;

    #[test]
    fn each_variant_reports_the_offending_length() {
        assert_eq!(
            format!("{}", InitError::InvalidKeyLength(7)),
            "invalid cipher key length: 7 bytes"
        );
        assert_eq!(
            format!("{}", InitError::InvalidIvLength(7)),
            "invalid cipher IV length: 7 bytes"
        );
        assert_eq!(
            format!("{}", InitError::InvalidRounds(256)),
            "invalid cipher round count: 256"
        );
    }
}
