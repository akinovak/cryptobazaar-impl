use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Debug)]
pub enum Error {
    OpeningAtZeroNotOne,
    RelationCheck,
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct Instance<C: CurveGroup> {
    pub n: usize,
    pub mu: C::ScalarField,
    pub acc_cm: C::Affine,
}

pub struct Witness<F: FftField> {
    pub acc: DensePolynomial<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<C: CurveGroup> {
    pub q: C::ScalarField,
    pub acc_opening: C::ScalarField,
    pub acc_shifted_opening: C::ScalarField,

    pub q_0: C::Affine,
    pub q_1: C::Affine,
    pub q_2: C::Affine,
}
