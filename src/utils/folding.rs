use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_std::{cfg_iter, One};
use std::ops::Mul;

use super::is_pow_2;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Debug)]
pub enum FoldError {
    TooShort,
    NotPowTwo,
}

pub trait Fold {
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

pub struct FFold<F: Field>(F);

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

pub struct AffFold<C: AffineRepr>(C);
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

pub fn compute_folding_coeffs<T>(chs: &[T]) -> Vec<T>
where
    T: Sized + Copy + One + Mul,
{
    let l = chs.len();

    let mut c: Vec<Vec<T>> = Vec::with_capacity(l);
    for i in 0..l {
        c.push(vec![T::one(); 1 << (i + 1)])
    }

    // first array is equal to [1][ch_0]
    c[0][1] = chs[0];

    for i in 0..(l - 1) {
        for j in 0..(1 << (i + 1)) {
            c[i + 1][2 * j] = c[i][j];
            c[i + 1][2 * j + 1] = chs[i + 1] * c[i][j];
        }
    }

    c[l - 1].clone()
}
