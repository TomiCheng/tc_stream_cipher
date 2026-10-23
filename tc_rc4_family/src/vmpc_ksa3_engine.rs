use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

use crate::vmpc_state::{self, VmpcState};

/// VMPC-KSA3, as Bouncy Castle's `VmpcKsa3Engine`: VMPC whose key schedule
/// mixes the key in once more after the IV, taking a key and an IV of 16 to 64
/// bytes each.
///
/// **Variable time (cache timing):** as [`VmpcEngine`](crate::VmpcEngine),
/// the positions it reads depend on secrets; kept for compatibility only. The
/// permutation, key and IV are wiped on drop.
pub struct VmpcKsa3Engine {
    state: VmpcState,
}

impl VmpcKsa3Engine {
    /// Shortest accepted key length in bytes.
    pub const MIN_KEY_BYTES: usize = vmpc_state::MIN_KEY_BYTES;
    /// Longest accepted key length in bytes.
    pub const MAX_KEY_BYTES: usize = vmpc_state::MAX_KEY_BYTES;
    /// Shortest accepted IV length in bytes.
    pub const MIN_IV_BYTES: usize = vmpc_state::MIN_IV_BYTES;
    /// Longest accepted IV length in bytes.
    pub const MAX_IV_BYTES: usize = vmpc_state::MAX_IV_BYTES;

    /// An engine without a key; `init` must come before processing. Constant
    /// time.
    pub const fn new() -> Self {
        Self {
            state: VmpcState::new(true),
        }
    }
}

impl Default for VmpcKsa3Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for VmpcKsa3Engine {
    /// Writes `VMPC-KSA3` without inspecting key material. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VMPC-KSA3")
    }
}

impl StreamCipher for VmpcKsa3Engine {
    type Error = StreamError;

    /// XORs `input` with the next keystream byte. Returns `NotInitialised`
    /// before `init`. Variable time (table lookups).
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        self.state.return_byte(input)
    }

    /// XORs `input` with the keystream into the start of `output` and returns
    /// `input.len()`. Returns `NotInitialised` before `init` and `BufferTooShort`
    /// if `output` is shorter than `input`; neither moves the position. Variable
    /// time (table lookups).
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        self.state.process_bytes(input, output)
    }

    /// Returns to the start of the keystream for the current key and IV.
    /// Variable time (the permutation is rebuilt).
    fn reset(&mut self) {
        self.state.reset();
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for VmpcKsa3Engine {
    type Error = InitError;

    /// Installs a key and an IV of 16 to 64 bytes each. The direction is ignored:
    /// both directions apply the same keystream. A rejected length leaves the
    /// previous key, IV and position in place. Variable time (the key schedule
    /// indexes the permutation with the key, the IV and the state).
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.state.init(params)
    }
}
