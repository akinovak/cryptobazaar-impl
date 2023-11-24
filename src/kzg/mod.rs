use std::{marker::PhantomData, ops::Mul};

use ark_ec::{pairing::Pairing, Group, VariableBaseMSM};
use ark_ff::One;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{SerializationError, Valid};

pub mod lagrange;

/// Minimal KZG functionalities
pub struct Kzg<E: Pairing> {
    _e: PhantomData<E>,
}

pub struct PK<E: Pairing> {
    pub srs: Vec<E::G1Affine>,
}

pub struct VK<E: Pairing> {
    g2: E::G2,
    x_g2: E::G2,
}

impl<E: Pairing> VK<E> {
    pub fn new(x_g2: E::G2) -> Self {
        Self {
            g2: E::G2::generator(),
            x_g2,
        }
    }
}

impl<E: Pairing> Kzg<E> {
    pub fn commit(pk: &PK<E>, poly: &DensePolynomial<E::ScalarField>) -> E::G1Affine {
        if pk.srs.len() - 1 < poly.degree() {
            panic!(
                "SRS size too small! Can't commit to polynomial of degree {} with srs of size {}",
                poly.degree(),
                pk.srs.len()
            );
        }

        let l = std::cmp::min(pk.srs.len(), poly.coeffs.len());
        E::G1::msm(&pk.srs[..l], &poly.coeffs).unwrap().into()
    }

    pub fn open(
        pk: &PK<E>,
        polys: &[DensePolynomial<E::ScalarField>],
        opening_challenge: E::ScalarField,
        separation_challenge: E::ScalarField,
    ) -> E::G1Affine {
        let powers_of_gamma = std::iter::successors(Some(E::ScalarField::one()), |p| {
            Some(*p * separation_challenge)
        });

        let mut batched = polys[0].clone();
        for (p_i, gamma_pow_i) in polys.iter().skip(1).zip(powers_of_gamma) {
            batched += (gamma_pow_i, p_i);
        }

        let q = &batched
            / &DensePolynomial::from_coefficients_slice(&[
                -opening_challenge,
                E::ScalarField::one(),
            ]);

        if pk.srs.len() - 1 < q.degree() {
            panic!(
                "Batch open g1: SRS size to small! Can't commit to polynomial of degree {} with srs of size {}",
                q.degree(),
                pk.srs.len()
            );
        }

        Kzg::commit(pk, &q)
    }

    pub fn verify(
        commitments: &[E::G1Affine],
        evaluations: &[E::ScalarField],
        opening_proof: E::G1Affine,
        opening_challenge: E::ScalarField,
        separation_challenge: E::ScalarField,
        vk: &VK<E>,
    ) -> Result<(), SerializationError> {
        assert_eq!(commitments.len(), evaluations.len());
        let powers_of_gamma: Vec<_> = std::iter::successors(Some(E::ScalarField::one()), |p| {
            Some(*p * separation_challenge)
        })
        .take(commitments.len())
        .collect();

        let batched_commitment = E::G1::msm(commitments, &powers_of_gamma).unwrap();
        let batched_eval: E::ScalarField = evaluations
            .iter()
            .zip(powers_of_gamma.iter())
            .map(|(&ei, &gamma_i)| ei * gamma_i)
            .sum();

        /*
            (p(X) - y) = q(X)(X - z)
            p(X) - y = q(X)•X - q(X)z
            p(X) - y + q(X)z = q(X)•X
            e([p] + z[q] - y[1], [1]) = e([q], [x])
        */

        let lhs = batched_commitment
            + opening_proof.mul(opening_challenge)
            + E::G1::generator().mul(-batched_eval);

        let mlo = E::multi_miller_loop(&[lhs, opening_proof.into()], &[vk.g2, vk.x_g2]);
        E::final_exponentiation(mlo).unwrap().check()
    }
}

#[cfg(test)]
mod test_kzg {
    use std::ops::Mul;

    use crate::utils::srs::unsafe_setup_from_tau;
    use ark_bn254::{Bn254, Fr as F, G1Projective, G2Projective};
    use ark_ec::Group;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::{test_rng, UniformRand};

    use super::{Kzg, PK, VK};

    #[test]
    fn batch_kzg() {
        let n = 16;
        let mut rng = test_rng();

        let a_coeffs: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let a_poly = DensePolynomial::from_coefficients_slice(&a_coeffs);

        let b_coeffs: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let b_poly = DensePolynomial::from_coefficients_slice(&b_coeffs);

        let tau = F::from(100);
        let srs = unsafe_setup_from_tau::<G1Projective>(n - 1, tau);
        let x_g2 = G2Projective::generator().mul(tau);

        let pk = PK::<Bn254> { srs: srs.clone() };

        let vk = VK::<Bn254>::new(x_g2);

        let a_cm = Kzg::commit(&pk, &a_poly);
        let b_cm = Kzg::commit(&pk, &b_poly);

        let z = F::from(10);
        let gamma = F::from(20);

        let a_eval = a_poly.evaluate(&z);
        let b_eval = b_poly.evaluate(&z);

        let q = Kzg::open(&pk, &[a_poly.clone(), b_poly.clone()], z, gamma);

        let verify_result = Kzg::verify(&[a_cm, b_cm], &[a_eval, b_eval], q, z, gamma, &vk);
        assert!(verify_result.is_ok());
    }
}
