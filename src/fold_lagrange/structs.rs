use ark_ec::CurveGroup;

use crate::univariate_sumcheck::structs::Proof as UVProof;
use crate::acc::structs::Proof as AccProof;

use crate::{acc::structs::Error as AccError, univariate_sumcheck::structs::Error as SumcheckError};

#[derive(Debug)]
pub enum Error {
    AccError,
    SumcheckError, 
}

impl From<AccError> for Error {
    fn from(_: AccError) -> Self {
        return Self::AccError
    }
}

impl From<SumcheckError> for Error {
    fn from(_: SumcheckError) -> Self {
        return Self::SumcheckError
    }
}


pub struct Instance<const N: usize, const LOG_N: usize, C: CurveGroup> {
    pub lb_commitments: [C::Affine; N],
    pub challenges: [C::ScalarField; LOG_N],
}

pub struct Proof<C: CurveGroup> {
    pub p_cm: C::Affine,
    pub acc_cm: C::Affine,
    pub acc_proof: AccProof<C>,
    pub sumcheck_proof: UVProof<C>,
}
