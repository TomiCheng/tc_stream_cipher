use tc_stream_cipher::{InitError, IvParams, KeyParams, StreamError};
use tc_zeroize::Zeroize;

const STATE_BYTES: usize = 256;
const KSA_STEPS: usize = 768;

pub(crate) const MIN_KEY_BYTES: usize = 16;
pub(crate) const MAX_KEY_BYTES: usize = 64;
pub(crate) const MIN_IV_BYTES: usize = 16;
pub(crate) const MAX_IV_BYTES: usize = 64;

/// The state VMPC and VMPC-KSA3 share; KSA3 only mixes the key in once more
/// after the IV.
pub(crate) struct VmpcState {
    permutation: [u8; STATE_BYTES],
    n: u8,
    s: u8,
    working_key: [u8; MAX_KEY_BYTES],
    key_len: usize,
    working_iv: [u8; MAX_IV_BYTES],
    iv_len: usize,
    ksa3: bool,
    initialised: bool,
}

impl VmpcState {
    pub(crate) const fn new(ksa3: bool) -> Self {
        Self {
            permutation: [0; STATE_BYTES],
            n: 0,
            s: 0,
            working_key: [0; MAX_KEY_BYTES],
            key_len: 0,
            working_iv: [0; MAX_IV_BYTES],
            iv_len: 0,
            ksa3,
            initialised: false,
        }
    }

    /// Key and IV each take 16 to 64 bytes, as in Bouncy Castle; a rejected
    /// length leaves the state untouched.
    pub(crate) fn init<P: KeyParams + IvParams + ?Sized>(
        &mut self,
        params: &P,
    ) -> Result<(), InitError> {
        let key = params.key();
        if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if !(MIN_IV_BYTES..=MAX_IV_BYTES).contains(&iv.len()) {
            return Err(InitError::InvalidIvLength(iv.len()));
        }
        self.working_key.zeroize();
        self.working_key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.working_iv.zeroize();
        self.working_iv[..iv.len()].copy_from_slice(iv);
        self.iv_len = iv.len();
        self.initialize_state();
        self.initialised = true;
        Ok(())
    }

    fn initialize_state(&mut self) {
        self.n = 0;
        self.s = 0;
        for (index, value) in self.permutation.iter_mut().enumerate() {
            *value = index as u8;
        }
        ksa_round(
            &mut self.permutation,
            &mut self.s,
            &self.working_key[..self.key_len],
        );
        ksa_round(
            &mut self.permutation,
            &mut self.s,
            &self.working_iv[..self.iv_len],
        );
        if self.ksa3 {
            ksa_round(
                &mut self.permutation,
                &mut self.s,
                &self.working_key[..self.key_len],
            );
        }
    }

    pub(crate) fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        Ok(input ^ self.next_byte())
    }

    pub(crate) fn process_bytes(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, StreamError> {
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

    fn next_byte(&mut self) -> u8 {
        let n = self.n as usize;
        let pn = self.permutation[n];
        self.s = self.permutation[self.s.wrapping_add(pn) as usize];
        let s = self.s as usize;
        let ps = self.permutation[s];
        let output = self.permutation[self.permutation[ps as usize].wrapping_add(1) as usize];
        self.permutation[n] = ps;
        self.permutation[s] = pn;
        self.n = self.n.wrapping_add(1);
        output
    }

    pub(crate) fn reset(&mut self) {
        if self.initialised {
            self.initialize_state();
        }
    }
}

impl Drop for VmpcState {
    fn drop(&mut self) {
        self.permutation.zeroize();
        self.working_key.zeroize();
        self.working_iv.zeroize();
    }
}

fn ksa_round(state: &mut [u8; STATE_BYTES], s: &mut u8, input: &[u8]) {
    for step in 0..KSA_STEPS {
        let index = step & 0xff;
        let value = state[index];
        *s = state[s
            .wrapping_add(value)
            .wrapping_add(input[step % input.len()]) as usize];
        state[index] = state[*s as usize];
        state[*s as usize] = value;
    }
}
