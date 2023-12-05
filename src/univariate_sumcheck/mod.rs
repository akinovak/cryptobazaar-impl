use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::univariate::DenseOrSparsePolynomial;
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_poly::{DenseUVPolynomial, Polynomial};
use structs::{Instance, Proof, Witness};

use crate::kzg::{Kzg, PK as KzgPk, VK as KzgVk};
use crate::utils::is_pow_2;

use self::structs::Error;
use self::tr::Transcript;

pub mod structs;
mod tr;

// TODO: wrap in SumcheckError
pub struct UnivariateSumcheck<E: Pairing> {
    _e: PhantomData<E>,
}

impl<E: Pairing> UnivariateSumcheck<E> {
    pub fn new_instance(
        n: usize,
        a_cm: E::G1Affine,
        b_cm: E::G1Affine,
        sum: E::ScalarField,
    ) -> Instance<E::G1> {
        assert!(is_pow_2(n));
        Instance { n, a_cm, b_cm, sum }
    }

    pub fn prove(
        witness: &Witness<E::ScalarField>,
        instance: &Instance<E::G1>,
        pk: &KzgPk<E>,
    ) -> Proof<E::G1> {
        assert!(is_pow_2(instance.n));
        let domain = GeneralEvaluationDomain::new(instance.n).unwrap();
        let mut tr = Transcript::new(b"univariate-sumcheck");

        tr.send_instance(instance);

        let ab = &witness.a_poly * &witness.b_poly;

        let (q, r) = DenseOrSparsePolynomial::from(ab.clone())
            .divide_with_q_and_r(&domain.vanishing_polynomial().into())
            .unwrap();

        let r_mod_x = DensePolynomial::from_coefficients_slice(&r.coeffs[1..]);

        let r_cm = Kzg::commit(pk, &r_mod_x);
        let q_cm = Kzg::commit(pk, &q);
        tr.send_r_and_q(&r_cm, &q_cm);

        let opening_challenge = tr.get_opening_challenge();

        let a_opening = witness.a_poly.evaluate(&opening_challenge);
        let b_opening = witness.b_poly.evaluate(&opening_challenge);

        let r_opening = r_mod_x.evaluate(&opening_challenge);
        let q_opening = q.evaluate(&opening_challenge);

        tr.send_openings(&a_opening, &b_opening, &r_opening, &q_opening);

        let separation_challenge = tr.get_separation_challenge();
        let pi = Kzg::open(
            pk,
            &[witness.a_poly.clone(), witness.b_poly.clone(), r_mod_x, q],
            opening_challenge,
            separation_challenge,
        );

        Proof {
            r_cm,
            q_cm,
            a_opening,
            b_opening,
            r_opening,
            q_opening,
            batch_opening_proof: pi,
        }
    }

    pub fn verify(
        proof: &Proof<E::G1>,
        instance: &Instance<E::G1>,
        vk: &KzgVk<E>,
    ) -> Result<(), Error> {
        assert!(is_pow_2(instance.n));
        let domain = GeneralEvaluationDomain::new(instance.n).unwrap();

        let commitments = [
            instance.a_cm.clone(),
            instance.b_cm.clone(),
            proof.r_cm.clone(),
            proof.q_cm.clone(),
        ];

        let evaluations = [
            proof.a_opening,
            proof.b_opening,
            proof.r_opening,
            proof.q_opening,
        ];

        let mut tr = Transcript::new(b"univariate-sumcheck");

        tr.send_instance(instance);
        tr.send_r_and_q(&proof.r_cm, &proof.q_cm);
        let opening_challenge = tr.get_opening_challenge();
        tr.send_openings(
            &proof.a_opening,
            &proof.b_opening,
            &proof.r_opening,
            &proof.q_opening,
        );
        let separation_challenge = tr.get_separation_challenge();

        // check a, b, r, q kzg opening proofs
        let opening_result = Kzg::verify(
            &commitments,
            &evaluations,
            proof.batch_opening_proof,
            opening_challenge,
            separation_challenge,
            vk,
        );

        assert!(opening_result.is_ok());

        let lhs = proof.a_opening * proof.b_opening;

        // check sumcheck relation
        let rhs = {
            let n_inv = E::ScalarField::from(instance.n as u64).inverse().unwrap();
            opening_challenge * proof.r_opening
                + instance.sum * n_inv
                + proof.q_opening * domain.evaluate_vanishing_polynomial(opening_challenge)
        };

        assert_eq!(lhs, rhs);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Mul;

    use super::*;
    use crate::kzg::{PK, VK};
    use crate::utils::srs::unsafe_setup_from_tau;

    use ark_bn254::{Bn254, Fr as F, G1Projective, G2Projective};
    use ark_ec::Group;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn sumcheck_test() {
        let mut rng = test_rng();
        let n = 16;
        let domain = GeneralEvaluationDomain::<F>::new(n).unwrap();

        let a_coeffs: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let a_poly = DensePolynomial::from_coefficients_slice(&a_coeffs);
        let a_evals: Vec<F> = domain.fft(&a_coeffs);

        let b_coeffs: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let b_poly = DensePolynomial::from_coefficients_slice(&b_coeffs);
        let b_evals: Vec<F> = domain.fft(&b_coeffs);

        let sum: F = a_evals
            .iter()
            .zip(b_evals.iter())
            .map(|(&ai, &bi)| ai * bi)
            .sum();

        let witness = Witness {
            a_poly: a_poly.clone(),
            b_poly: b_poly.clone(),
        };

        let tau = F::from(100);
        let srs = unsafe_setup_from_tau::<G1Projective>(n - 1, tau);
        let x_g2 = G2Projective::generator().mul(tau);

        let pk = PK::<Bn254> { srs: srs.clone() };
        let vk = VK::<Bn254>::new(x_g2);

        let a_cm = Kzg::commit(&pk, &a_poly);
        let b_cm = Kzg::commit(&pk, &b_poly);

        let instance = Instance::<G1Projective> { n, a_cm, b_cm, sum };

        let proof = UnivariateSumcheck::<Bn254>::prove(&witness, &instance, &pk);

        UnivariateSumcheck::<Bn254>::verify(&proof, &instance, &vk).unwrap();
    }
}
