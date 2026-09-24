//! Common stream-cipher error type.

use core::fmt;

/// Failures shared by stream-cipher implementations.
///
/// A stream cipher may use this type as its associated error or define an
/// algorithm-specific error type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamError {
    /// The cipher has not been initialized.
    NotInitialised,
    /// The output slice cannot hold the processed input.
    BufferTooShort,
    /// Processing the request would exceed the algorithm's byte limit.
    MaxBytesExceeded,
    /// The algorithm's block counter has been exhausted.
    CounterExhausted,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("stream cipher is not initialised"),
            Self::BufferTooShort => f.write_str("stream cipher output buffer is too short"),
            Self::MaxBytesExceeded => f.write_str("stream cipher byte limit exceeded"),
            Self::CounterExhausted => f.write_str("stream cipher counter exhausted"),
        }
    }
}

impl core::error::Error for StreamError {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::StreamError;

    #[test]
    fn each_variant_has_a_message() {
        for error in [
            StreamError::NotInitialised,
            StreamError::BufferTooShort,
            StreamError::MaxBytesExceeded,
            StreamError::CounterExhausted,
        ] {
            assert!(!format!("{error}").is_empty());
        }
    }
}
