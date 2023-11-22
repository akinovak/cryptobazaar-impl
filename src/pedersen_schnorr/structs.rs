use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Debug)]
pub enum Error {
    Relation1,
    Relation2,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<C: CurveGroup> {
    pub q_base: C::Affine,
    pub p_base: C::Affine,
    pub h_base: C::Affine,

    pub x_1: C::Affine,
    pub x_2: C::Affine,
}

pub struct Witness<F: Field> {
    pub a: F,
    pub r_1: F,
    pub r_2: F,
}

pub struct Proof<C: CurveGroup> {
    pub rand_1: C::Affine,
    pub rand_2: C::Affine,

    pub z_1: C::ScalarField,
    pub z_2: C::ScalarField,
    pub z_3: C::ScalarField,
}
