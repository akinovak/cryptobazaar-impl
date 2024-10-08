use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Debug)]
pub enum Error {
    RelationCheckFailed,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<C: CurveGroup> {
    pub p_base: C::Affine,
    pub h_base: C::Affine,

    pub x: C::Affine,
}

pub struct Witness<F: Field> {
    pub x: F,
    pub r: F,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<C: CurveGroup> {
    pub blinder: C::Affine,

    pub z_1: C::ScalarField,
    pub z_2: C::ScalarField,
}
