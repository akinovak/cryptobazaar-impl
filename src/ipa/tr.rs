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
        self.tr.send_message(b"pedersen-schnorr-instance", &data);
    }

    pub(crate) fn send_ls_rs(&mut self, l_1: &C::Affine, r_1: &C::Affine, l_2: &C::Affine, r_2: &C::Affine) {
        let mut data = Vec::new();

        l_1.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"l_1", &data);

        r_1.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r_1", &data);

        l_2.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"l_2", &data);

        r_2.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r_2", &data);
    }

    pub(crate) fn get_alpha_i(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"chi")
    }

    pub(crate) fn get_r(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"r")
    }
}
