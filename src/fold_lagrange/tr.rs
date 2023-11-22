use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;

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

    pub(crate) fn send_p(&mut self, p: &C::Affine) {
        let mut data = Vec::new();
        p.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"p", &data);
    }

    pub(crate) fn get_beta(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"beta")
    }
}
