use crate::gates::structs::Witness;
use ark_ec::CurveGroup;
use ark_ff::{batch_inversion, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};
use ark_std::{cfg_iter, UniformRand};
use rand::{RngCore, SeedableRng};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub struct BidEncoder<const P: usize, const N: usize, C: CurveGroup> {
    pub(crate) bid: [C::ScalarField; N],
    pub(crate) f: [C::ScalarField; N],
    pub(crate) r: [C::ScalarField; N],
}

impl<const P: usize, const N: usize, C: CurveGroup> BidEncoder<P, N, C> {
    pub fn encode<R: RngCore + SeedableRng>(bid: usize, seed: R::Seed) -> Self {
        assert!(bid <= P);
        let mut rng = R::from_seed(seed);

        let mut bid_encoding = vec![C::ScalarField::one(); bid];
        let mut zeroes = vec![C::ScalarField::zero(); P + 1 - bid];
        let mut blinders: Vec<_> = (0..(N - P - 1))
            .map(|_| C::ScalarField::rand(&mut rng))
            .collect();
        bid_encoding.append(&mut zeroes);
        bid_encoding.append(&mut blinders);

        let f: Vec<_> = (0..N).map(|_| C::ScalarField::rand(&mut rng)).collect();
        let r: Vec<_> = (0..N).map(|_| C::ScalarField::rand(&mut rng)).collect();

        Self {
            bid: bid_encoding.try_into().unwrap(),
            f: f.try_into().unwrap(),
            r: r.try_into().unwrap(),
        }
    }

    // TODO: all loops until P and after that blinders!
    pub fn to_gate_witness(&self) -> Witness<C::ScalarField> {
        let domain = GeneralEvaluationDomain::<C::ScalarField>::new(N).unwrap();

        let bid = DensePolynomial::from_coefficients_slice(&domain.ifft(&self.bid));
        let f = DensePolynomial::from_coefficients_slice(&domain.ifft(&self.f));
        let r = DensePolynomial::from_coefficients_slice(&domain.ifft(&self.r));

        let mut r_inv_evals = self.r;
        batch_inversion(&mut r_inv_evals);
        let r_inv = DensePolynomial::from_coefficients_slice(&domain.ifft(&r_inv_evals));

        let mut diff_evals = vec![C::ScalarField::zero(); N];
        let mut g_evals = vec![C::ScalarField::zero(); N];

        for i in 0..(N - 1) {
            diff_evals[i] = self.bid[i] - self.bid[i + 1];
            g_evals[i] = self.f[i] + self.bid[i] * self.r[i];
        }

        g_evals[N - 1] = self.f[N - 1] + self.bid[N - 1] * self.r[N - 1];

        let diff = DensePolynomial::from_coefficients_slice(&domain.ifft(&diff_evals));
        let g = DensePolynomial::from_coefficients_slice(&domain.ifft(&g_evals));

        Witness {
            bid,
            f,
            r,
            r_inv,
            diff,
            g,
        }
    }

    pub fn to_first_av_round(&self) -> Vec<C::Affine> {
        let gen = C::generator();
        let result: Vec<_> = cfg_iter!(self.f).map(|fi| gen.mul(fi)).collect();
        C::normalize_batch(&result)
    }

    pub fn to_second_av_round(&self) -> Vec<C::Affine> {
        let gen = C::generator();
        let result: Vec<_> = cfg_iter!(self.f)
            .zip(cfg_iter!(self.bid))
            .zip(cfg_iter!(self.r))
            .map(|((&fi, &bi), &ri)| gen.mul(fi + bi*ri))
            .collect();
        C::normalize_batch(&result)
    }
}

#[cfg(test)]
mod encoder_tests {
    use ark_bn254::{Fr as F, G1Projective};
    use ark_ff::{One, Zero};
    use rand_chacha::ChaCha20Rng;

    use super::BidEncoder;

    const P: usize = 5;
    const N: usize = 8;

    #[test]
    fn test_encode() {
        let bid = 4usize;
        // let enc = [1, 1, 1, 1, 0, 0, r1, r2];
        let enc = [F::one(), F::one(), F::one(), F::one(), F::zero(), F::zero()];

        let seed: [u8; 32] = [
            1, 0, 52, 0, 0, 0, 0, 0, 1, 0, 10, 0, 22, 32, 0, 0, 2, 0, 55, 49, 0, 11, 0, 0, 3, 0, 0,
            0, 0, 0, 2, 92,
        ];

        let encoder = BidEncoder::<P, N, G1Projective>::encode::<ChaCha20Rng>(bid, seed);
        assert_eq!(enc, encoder.bid[0..(P + 1)]);
    }
}
