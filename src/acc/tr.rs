use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;

use super::structs::Instance;
use crate::transcript::TranscriptOracle;

pub struct Transcript<C: CurveGroup> {
    tr: TranscriptOracle<C::ScalarField>,
}

impl<C: CurveGroup> Transcript<C> {
    pub(crate) fn new(init_label: &'static [u8]) -> Self {
        Self {
            tr: TranscriptOracle::new(init_label),
        }
    }

    pub(crate) fn send_instance(&mut self, instance: &Instance<C>) {
        let mut data = Vec::new();
        instance.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"acc-instance", &data);
    }

    pub(crate) fn send_q(&mut self, q: &C::ScalarField) {
        let mut data = Vec::new();
        q.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q", &data);
    }

    pub(crate) fn get_beta(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"beta")
    }
}
