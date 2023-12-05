use crate::double_pedersen_schnorr::structs::Proof as PSProof;
use crate::fold_lagrange::structs::Proof as LFProof;
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/*
    Prove statement that there exists a vector A such that for lagrange basis L, random basis B and public vector C:
        1. ∑ Ai*Li = ac
        2. forall i, Ai*Bi = C_i
*/

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<const N: usize, C: CurveGroup> {
    pub ac: C::Affine,
    pub lagrange_basis: [C::Affine; N],
    pub b: [C::Affine; N],
    pub h_base: C::Affine,
    pub c: [C::Affine; N],
}

pub struct Witness<const N: usize, F: FftField> {
    pub a: [F; N],
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<const LOG_N: usize, C: CurveGroup> {
    pub l_1: [C::Affine; LOG_N],
    pub r_1: [C::Affine; LOG_N],

    pub l_2: [C::Affine; LOG_N],
    pub r_2: [C::Affine; LOG_N],

    pub lf_proof: LFProof<C>,
    pub ps_proof: PSProof<C>,
}
