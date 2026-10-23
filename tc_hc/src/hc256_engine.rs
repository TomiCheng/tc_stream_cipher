use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

const TABLE_WORDS: usize = 1024;
const COUNTER_MASK: usize = 2047;
const FULL_KEY_BYTES: usize = 32;
const FULL_IV_BYTES: usize = 32;

/// HC-256 (Wu, 2004), as Bouncy Castle's `HC256Engine`: a 16- or 32-byte key
/// and an IV of at least 16 bytes. As in Bouncy Castle, a 16-byte key is
/// repeated to 32 bytes, an IV shorter than 32 bytes is filled from its start,
/// and only the first 32 bytes of a longer IV are used.
///
/// **Variable time (cache timing):** every step looks up the `p` and `q`
/// tables, including one cross lookup between them, at positions taken from the
/// secret state, which can leak where a cache is shared. HC has no
/// constant-time form; it is kept for compatibility. Everything else is 32-bit
/// additions, XORs and fixed rotations, branching only on lengths and the
/// position. The key, IV and both tables are wiped on drop.
pub struct Hc256Engine {
    p: [u32; TABLE_WORDS],
    q: [u32; TABLE_WORDS],
    counter: usize,
    key: [u8; FULL_KEY_BYTES],
    iv: [u8; FULL_IV_BYTES],
    word: [u8; 4],
    word_index: usize,
    initialised: bool,
}

impl Hc256Engine {
    /// Accepted key lengths in bytes.
    pub const KEY_BYTES: [usize; 2] = [16, 32];
    /// Shortest accepted IV length in bytes.
    pub const MIN_IV_BYTES: usize = 16;
    /// IV length in bytes that the cipher uses.
    pub const IV_BYTES: usize = FULL_IV_BYTES;

    /// An engine without a key; `init` must come before processing. Constant
    /// time.
    pub const fn new() -> Self {
        Self {
            p: [0; TABLE_WORDS],
            q: [0; TABLE_WORDS],
            counter: 0,
            key: [0; FULL_KEY_BYTES],
            iv: [0; FULL_IV_BYTES],
            word: [0; 4],
            word_index: 0,
            initialised: false,
        }
    }

    #[inline]
    fn step(&mut self) -> u32 {
        let index = self.counter & 1023;
        let index3 = index.wrapping_sub(3) & 1023;
        let index10 = index.wrapping_sub(10) & 1023;
        let index12 = index.wrapping_sub(12) & 1023;
        let index1023 = index.wrapping_sub(1023) & 1023;
        let result = if self.counter < 1024 {
            let x = self.p[index3];
            let y = self.p[index1023];
            let cross = self.q[((x ^ y) & 1023) as usize];
            self.p[index] = self.p[index]
                .wrapping_add(self.p[index10])
                .wrapping_add(x.rotate_right(10) ^ y.rotate_right(23))
                .wrapping_add(cross);
            let x = self.p[index12];
            let h = self.q[(x & 0xff) as usize]
                .wrapping_add(self.q[256 + ((x >> 8) & 0xff) as usize])
                .wrapping_add(self.q[512 + ((x >> 16) & 0xff) as usize])
                .wrapping_add(self.q[768 + ((x >> 24) & 0xff) as usize]);
            h ^ self.p[index]
        } else {
            let x = self.q[index3];
            let y = self.q[index1023];
            let cross = self.p[((x ^ y) & 1023) as usize];
            self.q[index] = self.q[index]
                .wrapping_add(self.q[index10])
                .wrapping_add(x.rotate_right(10) ^ y.rotate_right(23))
                .wrapping_add(cross);
            let x = self.q[index12];
            let h = self.p[(x & 0xff) as usize]
                .wrapping_add(self.p[256 + ((x >> 8) & 0xff) as usize])
                .wrapping_add(self.p[512 + ((x >> 16) & 0xff) as usize])
                .wrapping_add(self.p[768 + ((x >> 24) & 0xff) as usize]);
            h ^ self.q[index]
        };
        self.counter = (self.counter + 1) & COUNTER_MASK;
        result
    }

    fn initialize_state(&mut self) {
        self.counter = 0;
        self.word_index = 0;
        self.word = [0; 4];

        let mut words = [0u32; 2560];
        for (word, bytes) in words[..8].iter_mut().zip(self.key.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for (word, bytes) in words[8..16].iter_mut().zip(self.iv.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..words.len() {
            let x = words[index - 2];
            let y = words[index - 15];
            words[index] = (x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10))
                .wrapping_add(words[index - 7])
                .wrapping_add(y.rotate_right(7) ^ y.rotate_right(18) ^ (y >> 3))
                .wrapping_add(words[index - 16])
                .wrapping_add(index as u32);
        }
        self.p.copy_from_slice(&words[512..1536]);
        self.q.copy_from_slice(&words[1536..2560]);
        words.zeroize();
        for _ in 0..4096 {
            self.step();
        }
        self.counter = 0;
    }

    #[inline]
    fn next_byte(&mut self) -> u8 {
        if self.word_index == 0 {
            self.word = self.step().to_le_bytes();
        }
        let result = self.word[self.word_index];
        self.word_index = (self.word_index + 1) & 3;
        result
    }
}

impl Default for Hc256Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Hc256Engine {
    /// Writes `HC-256` without inspecting key material. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HC-256")
    }
}

impl StreamCipher for Hc256Engine {
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

    /// Returns to the start of the keystream for the current key and IV.
    /// Variable time (the tables are rebuilt with lookups).
    fn reset(&mut self) {
        if self.initialised {
            self.initialize_state();
        }
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Hc256Engine {
    type Error = InitError;

    /// Installs a 16- or 32-byte key and an IV of at least 16 bytes, filled out
    /// to 32 bytes as Bouncy Castle does. The direction is ignored: both directions
    /// apply the same keystream. A rejected length leaves the previous key, IV and
    /// position in place. Variable time (building the tables looks them up).
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !Self::KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() < Self::MIN_IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }

        if key.len() == FULL_KEY_BYTES {
            self.key.copy_from_slice(key);
        } else {
            self.key[..key.len()].copy_from_slice(key);
            self.key[key.len()..].copy_from_slice(key);
        }
        let copied = iv.len().min(FULL_IV_BYTES);
        self.iv[..copied].copy_from_slice(&iv[..copied]);
        if copied < FULL_IV_BYTES {
            let remaining = FULL_IV_BYTES - copied;
            self.iv[copied..].copy_from_slice(&iv[..remaining]);
        }
        self.initialize_state();
        self.initialised = true;
        Ok(())
    }
}

impl Drop for Hc256Engine {
    fn drop(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.key.zeroize();
        self.iv.zeroize();
        self.word.zeroize();
    }
}
