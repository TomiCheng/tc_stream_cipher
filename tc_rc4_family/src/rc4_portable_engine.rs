use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

const STATE_BYTES: usize = 256;

/// RC4 (Rivest, 1987) in portable Rust, as Bouncy Castle's `RC4Engine`: a key
/// of 1 to 256 bytes and no IV.
///
/// **Variable time (cache timing):** it swaps and outputs permutation entries
/// at indices taken from the permutation, so the positions depend on secrets.
/// RC4's keystream has known biases and the cipher is broken; it is kept for
/// compatibility only. The permutation and the key are wiped on drop.
pub struct Rc4PortableEngine {
    state: [u8; STATE_BYTES],
    x: usize,
    y: usize,
    working_key: [u8; Self::MAX_KEY_BYTES],
    key_len: usize,
    initialised: bool,
}

impl Rc4PortableEngine {
    /// Shortest accepted key length in bytes.
    pub const MIN_KEY_BYTES: usize = 1;
    /// Longest accepted key length in bytes.
    pub const MAX_KEY_BYTES: usize = 256;

    /// An engine without a key; `init` must come before processing. Constant
    /// time.
    pub const fn new() -> Self {
        Self {
            state: [0; STATE_BYTES],
            x: 0,
            y: 0,
            working_key: [0; Self::MAX_KEY_BYTES],
            key_len: 0,
            initialised: false,
        }
    }

    fn set_key(&mut self) {
        self.x = 0;
        self.y = 0;
        for (index, state) in self.state.iter_mut().enumerate() {
            *state = index as u8;
        }

        let mut key_index = 0usize;
        let mut state_index = 0usize;
        for index in 0..STATE_BYTES {
            state_index =
                (state_index + self.working_key[key_index] as usize + self.state[index] as usize)
                    & 0xff;
            self.state.swap(index, state_index);
            key_index = (key_index + 1) % self.key_len;
        }
    }

    fn next_byte(&mut self) -> u8 {
        self.x = (self.x + 1) & 0xff;
        self.y = (self.y + self.state[self.x] as usize) & 0xff;
        self.state.swap(self.x, self.y);
        let index = (self.state[self.x] as usize + self.state[self.y] as usize) & 0xff;
        self.state[index]
    }
}

impl Default for Rc4PortableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc4PortableEngine {
    /// Writes `RC4` without inspecting key material. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RC4")
    }
}

impl StreamCipher for Rc4PortableEngine {
    type Error = StreamError;

    /// XORs `input` with the next keystream byte. Returns `NotInitialised`
    /// before `init`. Variable time (table lookups).
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        Ok(input ^ self.next_byte())
    }

    /// XORs `input` with the keystream into the start of `output` and returns
    /// `input.len()`. Returns `NotInitialised` before `init` and `BufferTooShort`
    /// if `output` is shorter than `input`; neither moves the position. Variable
    /// time (table lookups).
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(StreamError::BufferTooShort);
        }
        for (input, output) in input.iter().zip(output.iter_mut()) {
            *output = *input ^ self.next_byte();
        }
        Ok(input.len())
    }

    /// Returns to the start of the keystream for the current key. Variable time
    /// (the permutation is rebuilt).
    fn reset(&mut self) {
        if self.initialised {
            self.set_key();
        }
    }
}

impl<P: KeyParams + ?Sized> StreamCipherInit<P> for Rc4PortableEngine {
    type Error = InitError;

    /// Installs a key of 1 to 256 bytes. The direction is ignored: both
    /// directions apply the same keystream. A rejected length leaves the previous
    /// key and position in place. Variable time (the key schedule indexes the
    /// permutation with the key and the state).
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !(Self::MIN_KEY_BYTES..=Self::MAX_KEY_BYTES).contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        self.working_key.zeroize();
        self.working_key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.set_key();
        self.initialised = true;
        Ok(())
    }
}

impl Drop for Rc4PortableEngine {
    fn drop(&mut self) {
        self.state.zeroize();
        self.working_key.zeroize();
    }
}
