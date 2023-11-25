use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;

use crate::transcript::TranscriptOracle;

use super::structs::VerifierIndex;

pub struct Transcript<C: CurveGroup> {
    tr: TranscriptOracle<C::ScalarField>,
}

impl<C: CurveGroup> Transcript<C> {
    pub(crate) fn new(init_label: &'static [u8]) -> Self {
        Self {
            tr: TranscriptOracle::new(init_label),
        }
    }

    pub(crate) fn send_index(&mut self, index: &VerifierIndex<C>) {
        let mut data = Vec::new();
        index.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"gates-v-index", &data);
    }

    pub(crate) fn send_oracle_commitments(
        &mut self,
        bid: &C::Affine,
        f: &C::Affine,
        r: &C::Affine,
        r_inv: &C::Affine,
        diff: &C::Affine,
        g: &C::Affine,
    ) {
        let mut data = Vec::new();

        bid.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"bid", &data);

        f.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"f", &data);

        r.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r", &data);

        r_inv.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r_inv", &data);

        diff.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"diff", &data);

        g.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"g", &data);
    }

    pub(crate) fn send_q_chunks(&mut self, q_chunk_0: &C::Affine, q_chunk_1: &C::Affine) {
        let mut data = Vec::new();

        q_chunk_0.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q_chunk_0", &data);

        q_chunk_1.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q_chunk_1", &data);
    }

    pub(crate) fn send_oracle_openings(
        &mut self,
        q_price: &C::ScalarField,
        bid: &C::ScalarField,
        bid_shift: &C::ScalarField,
        f: &C::ScalarField,
        r: &C::ScalarField,
        r_inv: &C::ScalarField,
        diff: &C::ScalarField,
        g: &C::ScalarField,
        q_chunk_0_opening: &C::ScalarField,
        q_chunk_1_opening: &C::ScalarField,
    ) {
        let mut data = Vec::new();

        q_price.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q_price", &data);

        bid.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"bid_eval", &data);

        bid_shift.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"bid_shift", &data);

        f.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"f_eval", &data);

        r.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r_eval", &data);

        r_inv.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r_inv_eval", &data);

        diff.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"diff_eval", &data);

        g.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"g_eval", &data);

        q_chunk_0_opening.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q_chunk_0_opening", &data);

        q_chunk_1_opening.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q_chunk_1_opening", &data);
    }

    pub(crate) fn get_quotient_challenge(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"quotient_challenge")
    }

    pub(crate) fn get_evaluation_challenge(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"evaluation_challenge")
    }

    pub(crate) fn get_separation_challenge(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"separation_challenge")
    }
}
