use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;

use crate::transcript::TranscriptOracle;

use super::structs::{Instance, VerifierIndex};

pub struct Transcript<C: CurveGroup> {
    tr: TranscriptOracle<C::ScalarField>,
}

impl<C: CurveGroup> Transcript<C> {
    pub(crate) fn new(init_label: &'static [u8]) -> Self {
        Self {
            tr: TranscriptOracle::new(init_label),
        }
    }

    pub(crate) fn send_v_index(&mut self, index: &VerifierIndex<C>) {
        let mut data = Vec::new();
        index.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"log-derivative-index", &data);
    }

    pub(crate) fn send_instance(&mut self, instance: &Instance<C>) {
        let mut data = Vec::new();
        instance.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"log-derivative-instance", &data);
    }

    pub(crate) fn send_blinders_sum(&mut self, bs: &C::ScalarField) {
        let mut data = Vec::new();
        bs.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"bs", &data);
    }

    pub(crate) fn send_b_and_q(&mut self, b: &C::Affine, q: &C::Affine) {
        let mut data = Vec::new();
        b.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"b", &data);

        q.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q", &data);
    }

    pub(crate) fn send_openings(
        &mut self,
        f_opening: &C::ScalarField,
        s_opening: &C::ScalarField,
        b_opening: &C::ScalarField,
        q_opening: &C::ScalarField,
    ) {
        let mut data = Vec::new();

        f_opening.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"f_opening", &data);

        s_opening.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"s_opening", &data);

        b_opening.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"b_opening", &data);

        q_opening.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q_opening", &data);
    }

    pub(crate) fn get_beta(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"beta")
    }

    pub(crate) fn get_mu(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"mu")
    }

    pub(crate) fn get_separation_challenge(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"separation-challenge")
    }
}
