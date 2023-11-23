use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Debug)]
pub enum Error {
    WellFormation,
    Sumcheck,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierIndex<C: CurveGroup> {
    pub s_cm: C::Affine,
}

pub struct ProverIndex<F: FftField> {
    pub s: DensePolynomial<F>,
    pub s_coset_evals: Vec<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<C: CurveGroup> {
    pub f_cm: C::Affine,
}

pub struct Witness<F: FftField> {
    pub f: DensePolynomial<F>,
}

pub struct Proof<C: CurveGroup> {
    pub gamma: C::ScalarField,

    pub b_cm: C::Affine,
    pub q_cm: C::Affine,

    pub f_opening: C::ScalarField,
    pub s_opening: C::ScalarField,
    pub b_opening: C::ScalarField,
    pub q_opening: C::ScalarField,

    pub q_0: C::Affine,
    pub q_1: C::Affine,
}
