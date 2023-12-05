use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Debug)]
pub enum Error {
    OpeningFailed,
    RelationCheckFailed,
    DegreeCheckShiftMissing,
    DegreeCheckFailed,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<C: CurveGroup> {
    pub(crate) n: usize,
    pub(crate) a_cm: C::Affine,
    pub(crate) c: C::ScalarField,
    pub(crate) sigma: C::ScalarField,
    pub(crate) blinder_cm: C::Affine,
    pub(crate) challenges: Vec<C::ScalarField>,
}

pub struct Witness<F: FftField> {
    pub(crate) a: DensePolynomial<F>,
    pub(crate) blinder: DensePolynomial<F>,
}

pub struct Proof<C: CurveGroup> {
    pub(crate) r_cm: C::Affine,
    pub(crate) r_degree_cm: C::Affine,
    pub(crate) q_cm: C::Affine,

    pub(crate) a_opening: C::ScalarField,
    pub(crate) blinder_opening: C::ScalarField,
    pub(crate) r_opening: C::ScalarField,
    pub(crate) q_opening: C::ScalarField,

    pub(crate) batch_opening_proof: C::Affine,
}
