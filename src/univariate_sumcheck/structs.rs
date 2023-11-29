use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Debug)]
pub enum Error {
    Error,
}

/// An instance for the univariate sumcheck argument,
/// for some witness a, b such that:
/// - a_cm = Comm(a),
/// - b_cm = Comm(b),
/// - sum = ∑ a_i • b_i
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<C: CurveGroup> {
    pub(crate) n: usize,
    pub(crate) a_cm: C::Affine,
    pub(crate) b_cm: C::Affine,
    pub(crate) sum: C::ScalarField,
}

pub struct Witness<F: FftField> {
    pub(crate) a_poly: DensePolynomial<F>,
    pub(crate) b_poly: DensePolynomial<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<C: CurveGroup> {
    pub(crate) r_cm: C::Affine,
    pub(crate) q_cm: C::Affine,
    // opening proofs
    pub(crate) a_opening: C::ScalarField,
    pub(crate) b_opening: C::ScalarField,
    pub(crate) r_opening: C::ScalarField,
    pub(crate) q_opening: C::ScalarField,

    pub(crate) batch_opening_proof: C::Affine,
}
