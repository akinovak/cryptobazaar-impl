use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Debug)]
pub enum Error {
    OpeningFailed,
    RelationCheckFailed,
    PedersenOpeningFailed,
    DegreeCheckShiftMissing,
    DegreeCheckFailed,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<C: CurveGroup> {
    pub(crate) n: usize,
    pub(crate) p_base: C::Affine,
    pub(crate) h_base: C::Affine,
    pub(crate) a_cm: C::Affine,
    pub(crate) pedersen: C::Affine,
    pub(crate) challenges: Vec<C::ScalarField>,
}

pub struct Witness<F: FftField> {
    pub(crate) a: DensePolynomial<F>,
    pub(crate) x: F,
    pub(crate) r: F,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<C: CurveGroup> {
    // round 1
    pub(crate) s: C::Affine,
    pub(crate) blinder_cm: C::Affine,

    // round 2
    pub(crate) z_1: C::ScalarField,
    pub(crate) z_2: C::ScalarField,
    pub(crate) r_cm: C::Affine,
    pub(crate) r_degree_cm: C::Affine,
    pub(crate) q_cm: C::Affine,

    // round 3
    pub(crate) a_opening: C::ScalarField,
    pub(crate) blinder_opening: C::ScalarField,
    pub(crate) r_opening: C::ScalarField,
    pub(crate) q_opening: C::ScalarField,

    // round 4
    pub(crate) batch_opening_proof: C::Affine,
}
