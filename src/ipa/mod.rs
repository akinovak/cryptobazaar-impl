use std::{
    marker::PhantomData,
    ops::Mul,
};

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_std::cfg_iter;

use crate::utils::is_pow_2;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub struct PedersenCommitment<const N: usize, C: CurveGroup> {
    ck: [C::Affine; N],
}

impl<const N: usize, C: CurveGroup> PedersenCommitment<N, C> {
    pub fn new(basis: &[C::Affine], h: C::Affine) -> Self {
        assert_eq!(basis.len(), N - 1);
        Self {
            ck: [basis, &[h]].concat().try_into().unwrap(),
        }
    }

    pub fn commit(&self, x: &[C::ScalarField], r: C::ScalarField) -> C {
        C::msm(&self.ck, &[x, &[r]].concat()).unwrap()
    }
}

#[derive(Debug)]
pub enum FoldError {
    TooShort,
    NotPowTwo,
}

trait Fold {
    type Challenge;
    type FoldType;
    fn check(x: &[Self::FoldType]) -> Result<(), FoldError> {
        if x.len() < 2 {
            return Err(FoldError::TooShort);
        }

        if !is_pow_2(x.len()) {
            return Err(FoldError::NotPowTwo);
        }

        Ok(())
    }
    fn fold_vec(
        x: &[Self::FoldType],
        ch: Self::Challenge,
    ) -> Result<Vec<Self::FoldType>, FoldError>;
}

struct FFold<F: Field>(F);

impl<F: Field> Fold for FFold<F> {
    type Challenge = F;
    type FoldType = F;
    fn fold_vec(
        x: &[Self::FoldType],
        ch: Self::Challenge,
    ) -> Result<Vec<Self::FoldType>, FoldError> {
        Self::check(x)?;

        let left = &x[..x.len() / 2];
        let right = &x[x.len() / 2..];

        Ok(cfg_iter!(left)
            .zip(cfg_iter!(right))
            .map(|(&l, &r)| l + r * ch)
            .collect())
    }
}

struct AffFold<C: AffineRepr>(C);
impl<C: AffineRepr> Fold for AffFold<C> {
    type Challenge = C::ScalarField;
    type FoldType = C;
    fn fold_vec(
        x: &[Self::FoldType],
        ch: Self::Challenge,
    ) -> Result<Vec<Self::FoldType>, FoldError> {
        Self::check(x)?;

        let left = &x[..x.len() / 2];
        let right = &x[x.len() / 2..];

        let projective_result: Vec<C::Group> = cfg_iter!(left)
            .zip(cfg_iter!(right))
            .map(|(&l, &r)| l + r * ch)
            .collect();

        Ok(C::Group::normalize_batch(&projective_result))
    }
}

pub struct DoubleInnerProduct<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup> DoubleInnerProduct<C> {
    pub fn run(x: &[C::ScalarField], b: &[C::Affine]) -> Result<(), FoldError> {
        assert_eq!(x.len(), b.len());
        assert!(is_pow_2(x.len()));

        let l = x.len().ilog2();

        let c = C::msm(b, x).unwrap();
        let mut c_fold = c.clone();

        let challenges = (0..l)
            .map(|i| C::ScalarField::from(10 + i))
            .collect::<Vec<C::ScalarField>>();

        let mut x_folded = x.clone().to_vec();
        let mut b_folded = b.clone().to_vec();

        #[cfg(feature = "parallel")]
        let num_chunks = rayon::current_num_threads();
        #[cfg(not(feature = "parallel"))]
        let num_chunks = 1;

        for i in 0..l as usize {
            let x_left = &x_folded[..x_folded.len() / 2];
            let x_right = &x_folded[x_folded.len() / 2..];

            let b_left = &b_folded[..b_folded.len() / 2];
            let b_right = &b_folded[b_folded.len() / 2..];

            let chunk_size = if num_chunks <= x_left.len() {
                x_left.len() / num_chunks
            } else {
                1
            };

            #[cfg(feature = "parallel")]
            let (x_left_chunks, b_right_chunks) = (
                x_left.par_chunks(chunk_size),
                b_right.par_chunks(chunk_size),
            );
            #[cfg(feature = "parallel")]
            let (x_right_chunks, b_left_chunks) = (
                x_right.par_chunks(chunk_size),
                b_left.par_chunks(chunk_size),
            );
            #[cfg(not(feature = "parallel"))]
            let (x_left_chunks, b_right_chunks) =
                (x_left.chunks(chunk_size), b_right.chunks(chunk_size));
            #[cfg(not(feature = "parallel"))]
            let (x_right_chunks, b_left_chunks) =
                (x_right.chunks(chunk_size), b_left.chunks(chunk_size));

            let left_msg: C = x_left_chunks
                .zip(b_right_chunks)
                .map(|(xli, bri)| C::msm(bri, xli).unwrap())
                .sum();
            let right_msg: C = x_right_chunks
                .zip(b_left_chunks)
                .map(|(xli, bri)| C::msm(bri, xli).unwrap())
                .sum();

            // let left_msg = C::msm(b_right, x_left).unwrap();
            // let right_msg = C::msm(b_left, x_right).unwrap();

            // send left and right
            // derive challenge
            let alpha = challenges[i];

            // fold vectors
            x_folded = FFold::fold_vec(&x_folded, alpha)?;
            b_folded = AffFold::fold_vec(&b_folded, alpha.inverse().unwrap())?;

            // derive new cm
            c_fold = left_msg.mul(alpha.inverse().unwrap()) + c_fold + right_msg.mul(alpha);
        }

        assert_eq!(b_folded.len(), 1);
        assert_eq!(x_folded.len(), 1);

        assert_eq!(b_folded[0].mul(x_folded[0]), c_fold);

        Ok(())
    }
}

#[cfg(test)]
mod ipa_tests {
    use std::ops::Mul;

    use ark_bn254::{Fr as F, G1Affine, G1Projective};
    use ark_ec::Group;
    use ark_std::UniformRand;

    use super::DoubleInnerProduct;

    #[test]
    fn test_simple_ipa() {
        let mut rng = ark_std::test_rng();
        let l = 7usize;
        let n = 1 << l;

        let gen = G1Projective::generator();
        let x: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let b: Vec<G1Affine> = (0..n).map(|_| gen.mul(F::rand(&mut rng)).into()).collect();

        DoubleInnerProduct::<G1Projective>::run(&x, &b).unwrap();
    }
}
