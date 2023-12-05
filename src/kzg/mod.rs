use std::{marker::PhantomData, ops::Mul, collections::BTreeMap};

use ark_ec::{pairing::Pairing, Group, VariableBaseMSM};
use ark_ff::One;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

pub mod lagrange;

#[derive(Debug)]
pub enum Error {
    PairingNot0,
}

/// Minimal KZG functionalities
pub struct Kzg<E: Pairing> {
    _e: PhantomData<E>,
}

pub struct PK<E: Pairing> {
    pub srs: Vec<E::G1Affine>,
}

pub struct VK<E: Pairing> {
    pub g2: E::G2,
    pub neg_x_g2: E::G2,
}

pub struct DegreeCheckVK<E: Pairing> {
    pub pk_max_degree: usize,
    pub shifts: BTreeMap<usize, E::G2>
}

impl<E: Pairing> DegreeCheckVK<E> {
    pub fn get_shift(&self, degree_bound: usize) -> Option<&E::G2> {
        let shift_factor = self.pk_max_degree - degree_bound;
        self.shifts.get(&shift_factor)
    }
}

impl<E: Pairing> VK<E> {
    pub fn new(x_g2: E::G2) -> Self {
        Self {
            g2: E::G2::generator(),
            neg_x_g2: -x_g2,
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

        E::G1::msm(&pk.srs[..poly.coeffs.len()], &poly.coeffs)
            .unwrap()
            .into()
    }

    pub fn open(
        pk: &PK<E>,
        polys: &[DensePolynomial<E::ScalarField>],
        opening_challenge: E::ScalarField,
        separation_challenge: E::ScalarField,
    ) -> E::G1Affine {
        let powers_of_gamma = std::iter::successors(Some(separation_challenge), |p| {
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
    ) -> Result<(), Error> {
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
            e([p] + z[q] - y[1], [1])*e([q], -[x]) = 0
        */

        let lhs = batched_commitment
            + opening_proof.mul(opening_challenge)
            + E::G1::generator().mul(-batched_eval);

        let mlo = E::multi_miller_loop(&[lhs, opening_proof.into()], &[vk.g2, vk.neg_x_g2]);
        let res = E::final_exponentiation(mlo).unwrap().0;
        if res != E::TargetField::one() {
            return Err(Error::PairingNot0);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test_kzg {
    use std::{ops::Mul, collections::BTreeMap};

    use crate::utils::srs::unsafe_setup_from_tau;
    use ark_bn254::{Bn254, Fr as F, G1Projective, G2Projective};
    use ark_ec::{Group, pairing::Pairing};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::{test_rng, UniformRand};
    use ark_ff::{Zero, Field};

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

    #[test]
    fn test_degree_bound() {
        let n = 16;
        let mut rng = test_rng();

        let a_coeffs: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let a_poly = DensePolynomial::from_coefficients_slice(&a_coeffs);

        let tau = F::from(100);
        let srs = unsafe_setup_from_tau::<G1Projective>(2*n - 1, tau);

        let shift_factor = srs.len() - 1 - (n - 1);
        let tau_pow_shift = G2Projective::generator().mul(tau.pow(&[shift_factor as u64]));
        let mut degree_check_vk_map: BTreeMap<usize, G2Projective> = BTreeMap::new();
        degree_check_vk_map.insert(shift_factor, tau_pow_shift);

        // we want to check that a is of degree <= n-1
        let a_degree = {
            let mut coeffs = a_poly.coeffs().clone().to_vec();
            let mut shifted_coeffs = vec![F::zero(); shift_factor];
            shifted_coeffs.append(&mut coeffs);
            DensePolynomial::from_coefficients_slice(&shifted_coeffs)
        };

        let pk = PK::<Bn254> { srs: srs.clone() };
        let a_cm = Kzg::commit(&pk, &a_poly);
        let a_degree_cm = Kzg::commit(&pk, &a_degree);

        let lhs = Bn254::pairing(a_cm, degree_check_vk_map.get(&shift_factor).unwrap());
        let rhs = Bn254::pairing(a_degree_cm, G2Projective::generator());
        assert_eq!(lhs, rhs);
    }
}