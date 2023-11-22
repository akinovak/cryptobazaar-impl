use ark_ff::PrimeField;
use ark_serialize::Compress;
use merlin::Transcript as Tr;
use std::marker::PhantomData;
use std::sync::Mutex;

/// Generic structure that serves same interface to all subprotocols
/// Makes it thread safe
pub struct TranscriptOracle<F: PrimeField> {
    tr: Mutex<Tr>,
    challenge_buffer: Mutex<Vec<u8>>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> TranscriptOracle<F> {
    pub fn new(init_label: &'static [u8]) -> Self {
        let tr = Tr::new(init_label);
        let challenge_size = F::zero().serialized_size(Compress::No);
        let challenge_buffer = vec![0u8; challenge_size];
        Self {
            tr: Mutex::new(tr),
            challenge_buffer: Mutex::new(challenge_buffer),
            _f: PhantomData,
        }
    }

    pub fn send_message(&mut self, label: &'static [u8], data: &[u8]) {
        let mut tr = self.tr.lock().unwrap();
        tr.append_message(label, data);
    }

    pub fn squeeze_challenge(&mut self, label: &'static [u8]) -> F {
        let mut tr = self.tr.lock().unwrap();
        let mut ch_buffer = self.challenge_buffer.lock().unwrap();

        tr.challenge_bytes(label, &mut ch_buffer);
        F::from_be_bytes_mod_order(&ch_buffer)
    }
}
