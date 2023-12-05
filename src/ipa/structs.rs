use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::verifiable_folding_sumcheck::structs::Proof as VFSProof;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<const N: usize, C: CurveGroup> {
    pub ac: C::Affine,
    pub b: [C::Affine; N],
    pub h_base: C::Affine,
    pub c: [C::Affine; N],
}

pub struct Witness<const N: usize, F: FftField> {
    pub a: [F; N],
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<const LOG_N: usize, C: CurveGroup> {
    pub l: [C::Affine; LOG_N],
    pub r: [C::Affine; LOG_N],

    pub vfs_proof: VFSProof<C>,
}
