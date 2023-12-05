use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;

use super::structs::Instance;
use crate::transcript::TranscriptOracle;

pub struct Transcript<const N: usize, const LOG_N: usize, C: CurveGroup> {
    tr: TranscriptOracle<C::ScalarField>,
}

impl<const N: usize, const LOG_N: usize, C: CurveGroup> Transcript<N, LOG_N, C> {
    pub(crate) fn new(init_label: &'static [u8]) -> Self {
        Self {
            tr: TranscriptOracle::new(init_label),
        }
    }

    pub(crate) fn send_instance(&mut self, instance: &Instance<N, C>) {
        let mut data = Vec::new();
        instance.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"ipa-instance", &data);
    }

    pub(crate) fn send_l_r(&mut self, l: &C::Affine, r: &C::Affine) {
        let mut data = Vec::new();

        l.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"l", &data);

        r.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r", &data);
    }

    pub(crate) fn get_alpha_i(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"chi")
    }

    pub(crate) fn get_r(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"r")
    }
}
