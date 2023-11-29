use ark_ec::CurveGroup;
use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub struct Oracle<'a, F: Field>(pub(crate) &'a [F]);


#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierIndex<C: CurveGroup> {
    pub q_price_cm: C::Affine,
}

pub struct ProverIndex<F: FftField> {
    pub q_price: DensePolynomial<F>,
    pub q_price_coset_evals: Vec<F>,
    pub l_p_next_coset_evals: Vec<F>,
}

pub struct Witness<F: FftField> {
    pub bid: DensePolynomial<F>,
    pub f: DensePolynomial<F>,
    pub r: DensePolynomial<F>,
    pub r_inv: DensePolynomial<F>,
    pub diff: DensePolynomial<F>,
    pub g: DensePolynomial<F>,
}

pub struct Proof<C: CurveGroup> {
    pub bid_cm: C::Affine,
    pub r_cm: C::Affine,
    pub r_inv_cm: C::Affine,
    pub f_cm: C::Affine,
    pub diff_cm: C::Affine,
    pub g_cm: C::Affine,

    pub q_price_opening: C::ScalarField,
    pub bid_opening: C::ScalarField,
    pub bid_shift_opening: C::ScalarField,
    pub f_opening: C::ScalarField,
    pub r_opening: C::ScalarField,
    pub r_inv_opening: C::ScalarField,
    pub diff_opening: C::ScalarField,
    pub g_opening: C::ScalarField,

    pub q_chunk_0_cm: C::Affine,
    pub q_chunk_1_cm: C::Affine,

    pub q_chunk_0_opening: C::ScalarField,
    pub q_chunk_1_opening: C::ScalarField,

    pub w_0: C::Affine,
    pub w_1: C::Affine,
}
