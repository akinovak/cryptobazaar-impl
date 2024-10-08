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
        self.tr.send_message(b"pedersen-schnorr-instance", &data);
    }

    pub(crate) fn send_blinder(&mut self, blinder: &C::Affine) {
        let mut data = Vec::new();
        blinder.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"blinder", &data);
    }

    pub(crate) fn get_c(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"c")
    }
}
