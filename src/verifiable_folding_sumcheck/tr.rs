use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;

use crate::transcript::TranscriptOracle;

use super::structs::Instance;

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
        self.tr.send_message(b"verifiable-folding-instance", &data);
    }

    pub(crate) fn send_oracles(&mut self, r: &C::Affine, r_degree: &C::Affine, q: &C::Affine) {
        let mut data = Vec::new();

        r.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r", &data);

        r_degree.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r_degree", &data);

        q.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q", &data);
    }

    pub(crate) fn send_openings(
        &mut self,
        a_opening: &C::ScalarField,
        blinder_opening: &C::ScalarField,
        r_opening: &C::ScalarField,
        q_opening: &C::ScalarField,
    ) {
        let mut data = Vec::new();

        a_opening.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"a_opening", &data);

        blinder_opening.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"blinder_opening", &data);

        r_opening.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r_opening", &data);

        q_opening.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q_opening", &data);
    }

    pub(crate) fn get_opening_challenge(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"opening_challenge")
    }

    pub(crate) fn get_separation_challenge(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"separation_challenge")
    }
}
