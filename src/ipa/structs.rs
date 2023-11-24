use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use crate::pedersen_schnorr::structs::Proof as PSProof;

/*
    Prove statement that there exists a vector A such that for bases: (B_1, B_2) and public vector C: 
        1. ∑ Ai*B_1i = ac
        2. forall i, Ai*B_2i = C_i
*/

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<const N: usize, C: CurveGroup> {
    pub ac: C::Affine, 
    pub base_1: [C::Affine; N], 
    pub base_2: [C::Affine; N], 
    pub h_base: C::Affine,
    pub c: [C::Affine; N]
}

pub struct Witness<const N: usize, F: FftField> {
    pub a: [F; N]
}

pub struct Proof<const LOG_N: usize, C: CurveGroup> {
    pub l_1: [C::Affine; LOG_N], 
    pub r_1: [C::Affine; LOG_N], 

    pub l_2: [C::Affine; LOG_N], 
    pub r_2: [C::Affine; LOG_N],

    pub ps_proof: PSProof<C>
}