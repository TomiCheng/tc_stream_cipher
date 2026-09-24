//! The ChaCha block function and the keystream state the engines share.

use tc_stream_cipher::StreamError;
use tc_zeroize::Zeroize;

use crate::BLOCK_BYTES;

pub(crate) const STATE_WORDS: usize = 16;

/// Bouncy Castle's per-IV byte limit: a key and IV stop just before 2^69
/// bytes. Only the original 64-bit counter can get near it.
const MAX_BYTES: u128 = 1 << 69;

const TAU: [u32; 4] = [0x6170_7865, 0x3120_646e, 0x7962_2d36, 0x6b20_6574];
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// How the block counter is laid out in the state.
#[derive(Clone, Copy)]
pub(crate) enum Counter {
    /// Words 12 and 13: a 64-bit counter beside a 64-bit nonce.
    Original,
    /// Word 12 only: a 32-bit counter beside a 96-bit nonce.
    Ietf,
}

/// Keystream state: the input words, the current keystream block and the
/// position in it.
pub(crate) struct State {
    rounds: usize,
    words: [u32; STATE_WORDS],
    key_stream: [u8; BLOCK_BYTES],
    index: usize,
    processed: u128,
    counter: Counter,
    counter_exhausted: bool,
    initialised: bool,
}

impl State {
    pub(crate) const fn new(rounds: usize, counter: Counter) -> Self {
        Self {
            rounds,
            words: [0; STATE_WORDS],
            key_stream: [0; BLOCK_BYTES],
            index: 0,
            processed: 0,
            counter,
            counter_exhausted: false,
            initialised: false,
        }
    }

    /// Loads a 16- or 32-byte key and an 8-byte IV with the 64-bit counter.
    pub(crate) fn init_original(&mut self, key: &[u8], iv: &[u8]) {
        self.words = [0; STATE_WORDS];
        set_key(&mut self.words, key);
        load_words(iv, &mut self.words[14..]);
        self.counter = Counter::Original;
        self.reset();
        self.initialised = true;
    }

    /// Loads a 32-byte key and a 12-byte IV with the 32-bit counter.
    pub(crate) fn init_ietf(&mut self, key: &[u8], iv: &[u8]) {
        self.words = [0; STATE_WORDS];
        set_key(&mut self.words, key);
        load_words(iv, &mut self.words[13..]);
        self.counter = Counter::Ietf;
        self.reset();
        self.initialised = true;
    }

    pub(crate) fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        let mut output = [0];
        self.process_bytes(&[input], &mut output)?;
        Ok(output[0])
    }

    /// Checks every limit before writing, so an error leaves `output` and
    /// the position unchanged.
    pub(crate) fn process_bytes(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        let output = output
            .get_mut(..input.len())
            .ok_or(StreamError::BufferTooShort)?;
        let length = input.len() as u128;
        if self.processed + length >= MAX_BYTES {
            return Err(StreamError::MaxBytesExceeded);
        }
        if matches!(self.counter, Counter::Ietf) && length > self.remaining_ietf() {
            return Err(StreamError::CounterExhausted);
        }

        for (input, output) in input.iter().zip(output) {
            *output = *input ^ self.next_byte();
        }
        self.processed += length;
        Ok(input.len())
    }

    pub(crate) fn reset(&mut self) {
        self.index = 0;
        self.processed = 0;
        self.counter_exhausted = false;
        self.words[12] = 0;
        if matches!(self.counter, Counter::Original) {
            self.words[13] = 0;
        }
    }

    /// Bytes left before the 32-bit counter runs out: the rest of the
    /// current block plus every block the counter can still reach.
    fn remaining_ietf(&self) -> u128 {
        let buffered = if self.index == 0 {
            0
        } else {
            BLOCK_BYTES - self.index
        };
        let blocks = if self.counter_exhausted {
            0
        } else {
            (1_u128 << 32) - u128::from(self.words[12])
        };
        buffered as u128 + blocks * BLOCK_BYTES as u128
    }

    /// The caller has checked that the keystream reaches this far.
    fn next_byte(&mut self) -> u8 {
        if self.index == 0 {
            self.key_stream = block(self.rounds, &self.words);
            self.advance_counter();
        }
        let output = self.key_stream[self.index];
        self.index = (self.index + 1) % BLOCK_BYTES;
        output
    }

    fn advance_counter(&mut self) {
        match self.counter {
            Counter::Original => {
                self.words[12] = self.words[12].wrapping_add(1);
                if self.words[12] == 0 {
                    self.words[13] = self.words[13].wrapping_add(1);
                }
            }
            Counter::Ietf => {
                if self.words[12] == u32::MAX {
                    self.counter_exhausted = true;
                } else {
                    self.words[12] += 1;
                }
            }
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.words.zeroize();
        self.key_stream.zeroize();
    }
}

/// Writes the constants and a 16- or 32-byte key into words 0 to 11; a
/// 16-byte key fills both key halves.
pub(crate) fn set_key(words: &mut [u32; STATE_WORDS], key: &[u8]) {
    words[..4].copy_from_slice(if key.len() == 16 { &TAU } else { &SIGMA });
    load_words(&key[..16], &mut words[4..8]);
    load_words(&key[key.len() - 16..], &mut words[8..12]);
}

/// Reads little-endian words from `bytes`, which holds four bytes per word.
pub(crate) fn load_words(bytes: &[u8], words: &mut [u32]) {
    for (index, word) in words.iter_mut().enumerate() {
        let at = index * 4;
        *word = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    }
}

/// Writes `words` little-endian into `bytes`, which holds four bytes per word.
pub(crate) fn store_words(words: &[u32], bytes: &mut [u8]) {
    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}

/// One keystream block: the permutation plus the input words.
pub(crate) fn block(rounds: usize, input: &[u32; STATE_WORDS]) -> [u8; BLOCK_BYTES] {
    let mut words = permutation(rounds, input);
    for (word, original) in words.iter_mut().zip(input) {
        *word = word.wrapping_add(*original);
    }
    let mut output = [0u8; BLOCK_BYTES];
    store_words(&words, &mut output);
    words.zeroize();
    output
}

/// `rounds` rounds, alternating column and diagonal rounds; `rounds` is even.
pub(crate) fn permutation(rounds: usize, input: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut state = *input;
    for _ in (0..rounds).step_by(2) {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);

        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    state
}

#[inline]
fn quarter_round(
    state: &mut [u32; STATE_WORDS],
    a_index: usize,
    b_index: usize,
    c_index: usize,
    d_index: usize,
) {
    let (mut a, mut b, mut c, mut d) = (
        state[a_index],
        state[b_index],
        state[c_index],
        state[d_index],
    );

    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(16);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(12);
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(8);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(7);

    state[a_index] = a;
    state[b_index] = b;
    state[c_index] = c;
    state[d_index] = d;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ietf_state() -> State {
        let mut state = State::new(20, Counter::Ietf);
        state.init_ietf(&[0; 32], &[0; 12]);
        state
    }

    #[test]
    fn the_byte_limit_rejects_a_request_up_front_and_keeps_the_position() {
        let mut state = State::new(20, Counter::Original);
        state.init_original(&[0; 32], &[0; 8]);
        state.processed = MAX_BYTES - 2;
        let mut output = [0x55; 2];
        assert_eq!(
            state.process_bytes(&[0; 2], &mut output),
            Err(StreamError::MaxBytesExceeded)
        );
        assert_eq!(output, [0x55; 2]);
        assert_eq!(state.process_bytes(&[0], &mut output), Ok(1));
        assert_eq!(state.return_byte(0), Err(StreamError::MaxBytesExceeded));
    }

    #[test]
    fn the_ietf_counter_serves_its_last_block_and_then_rejects_without_writing() {
        let mut state = ietf_state();
        state.words[12] = u32::MAX;
        let mut output = [0x55; BLOCK_BYTES + 1];
        assert_eq!(
            state.process_bytes(&[0; BLOCK_BYTES + 1], &mut output),
            Err(StreamError::CounterExhausted)
        );
        assert_eq!(output, [0x55; BLOCK_BYTES + 1]);

        assert_eq!(state.process_bytes(&[0; 10], &mut output), Ok(10));
        assert_eq!(
            state.process_bytes(&[0; BLOCK_BYTES - 9], &mut output),
            Err(StreamError::CounterExhausted)
        );
        assert_eq!(
            state.process_bytes(&[0; BLOCK_BYTES - 10], &mut output),
            Ok(BLOCK_BYTES - 10)
        );
        assert_eq!(state.return_byte(0), Err(StreamError::CounterExhausted));

        state.reset();
        assert_eq!(state.return_byte(0).map(|_| ()), Ok(()));
    }

    #[test]
    fn a_fresh_ietf_state_can_reach_exactly_two_to_the_thirty_two_blocks() {
        assert_eq!(
            ietf_state().remaining_ietf(),
            (1 << 32) * BLOCK_BYTES as u128
        );
    }
}
