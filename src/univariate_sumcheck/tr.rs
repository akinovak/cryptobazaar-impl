use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;

use crate::transcript::TranscriptOracle;

use super::structs::Instance;

/*
    Instance: |H|, µ, [a], [b]
    Prover sends: [r], [q]
    Verifier sends: ß
    Prover sends: a(ß), b(ß), r(ß), q(ß)
    Verifier sends: ∂
    Prover sends: [π]
    Verifier checks:
    1. a(ß) • b(ß) == ßr(ß) + µ/|H| + q(ß)•zH(ß)
    2. e([a] + ∂[b] + ∂^2[r] + ∂^3[q] + ß[π] - [a(ß) + ∂b(ß) + ∂^2r(ß) + ∂^3q(ß), [1]) == e([π], [x])
*/
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
        self.tr.send_message(b"univariate-sumcheck-instance", &data);
    }

    pub(crate) fn send_r_and_q(&mut self, r_cm: &C::Affine, q_cm: &C::Affine) {
        let mut data = Vec::new();
        r_cm.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r", &data);

        q_cm.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q", &data);
    }

    pub(crate) fn send_openings(
        &mut self,
        a_eval: &C::ScalarField,
        b_eval: &C::ScalarField,
        r_eval: &C::ScalarField,
        q_eval: &C::ScalarField,
    ) {
        let mut data = Vec::new();

        a_eval.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"a_eval", &data);

        b_eval.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"b_eval", &data);

        r_eval.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"r_eval", &data);

        q_eval.serialize_uncompressed(&mut data).unwrap();
        self.tr.send_message(b"q_eval", &data);
    }

    pub(crate) fn get_opening_challenge(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"opening_challenge")
    }

    pub(crate) fn get_separation_challenge(&mut self) -> C::ScalarField {
        self.tr.squeeze_challenge(b"separation_challenge")
    }
}
