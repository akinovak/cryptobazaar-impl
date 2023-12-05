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

    pub(crate) fn send_blinders(&mut self, s: &C::Affine, blinder: &C::Affine) {
        let mut data = Vec::new();

        s.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"s", &data);

        blinder.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"blinder", &data);
    }

    pub(crate) fn second_round(
        &mut self,
        z_1: &C::ScalarField,
        z_2: &C::ScalarField,
        r_cm: &C::Affine,
        r_degree_cm: &C::Affine,
        q_cm: &C::Affine,
    ) {
        let mut points_data = Vec::new();
        let mut scalars_data = Vec::new();

        r_cm.serialize_uncompressed(&mut points_data).unwrap();
        self.tr.send_message(b"r", &points_data);

        r_degree_cm
            .serialize_uncompressed(&mut points_data)
            .unwrap();
        self.tr.send_message(b"r_degree", &points_data);

        q_cm.serialize_uncompressed(&mut points_data).unwrap();
        self.tr.send_message(b"q", &points_data);

        z_1.serialize_uncompressed(&mut scalars_data).unwrap();
        self.tr.send_message(b"z_1", &scalars_data);

        z_2.serialize_uncompressed(&mut scalars_data).unwrap();
        self.tr.send_message(b"z_2", &scalars_data);
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

    pub(crate) fn get_c(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"c")
    }

    pub(crate) fn get_opening_challenge(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"opening_challenge")
    }

    pub(crate) fn get_separation_challenge(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"separation_challenge")
    }
}
