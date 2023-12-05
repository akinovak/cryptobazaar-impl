use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::{Field, Zero, One};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
};
use ark_std::cfg_iter;
use rand::{RngCore, SeedableRng};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use self::structs::{Error, Instance, Proof, Witness};
use crate::{
    kzg::{Kzg, PK as KzgPk, VK as KzgVk, DegreeCheckVK},
    utils::{folding::compute_folding_coeffs, is_pow_2},
    verifiable_folding_sumcheck::tr::Transcript,
};

pub mod structs;
mod tr;

pub struct Argument<E: Pairing> {
    _e: PhantomData<E>,
}

impl<E: Pairing> Argument<E> {
    pub fn sample_blinder<R: RngCore + SeedableRng>(
        sum: E::ScalarField,
        degree: usize,
        n: u64,
        seed: R::Seed,
    ) -> DensePolynomial<E::ScalarField> {
        let mut rng = R::from_seed(seed);
        let mut blinder = DensePolynomial::<E::ScalarField>::rand(degree, &mut rng);

        let n_inv = E::ScalarField::from(n).inverse().unwrap();
        blinder[0] = sum * n_inv;

        blinder
    }

    pub fn prove(
        instance: &Instance<E::G1>,
        witness: &Witness<E::ScalarField>,
        pk: &KzgPk<E>,
    ) -> Proof<E::G1> {
        assert!(is_pow_2(instance.n));
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(instance.n).unwrap();
        let mut tr = Transcript::new(b"verifiable-folding-sumcheck");

        tr.send_instance(instance);

        let b_evals = compute_folding_coeffs::<E::ScalarField>(&instance.challenges);
        let b: DensePolynomial<<E as Pairing>::ScalarField> =
            DensePolynomial::from_coefficients_slice(&domain.ifft(&b_evals));

        // B(X) + ca(X)b(X)
        let lhs = &witness.blinder + &(&(&witness.a * &b) * instance.c);

        let (q, r) = DenseOrSparsePolynomial::from(lhs.clone())
            .divide_with_q_and_r(&domain.vanishing_polynomial().into())
            .unwrap();
        assert_eq!(
            instance.sigma,
            E::ScalarField::from(instance.n as u64) * r[0]
        );
        let r_mod_x = DensePolynomial::from_coefficients_slice(&r.coeffs[1..]);

        // deg(r_mod_x) <= n - 2
        let r_degree = {
            let shift_factor = pk.srs.len() - 1 - (instance.n - 2);
            let mut coeffs = r_mod_x.coeffs().clone().to_vec();
            let mut shifted_coeffs = vec![E::ScalarField::zero(); shift_factor];
            shifted_coeffs.append(&mut coeffs);
            DensePolynomial::from_coefficients_slice(&shifted_coeffs)
        };

        let r_mod_x_cm = Kzg::commit(pk, &r_mod_x);
        let r_degree_cm = Kzg::commit(pk, &r_degree);
        let q_cm = Kzg::commit(pk, &q);

        tr.send_oracles(&r_mod_x_cm, &r_degree_cm, &q_cm);
        let opening_challenge = tr.get_opening_challenge();

        let a_opening = witness.a.evaluate(&opening_challenge);
        let blinder_opening = witness.blinder.evaluate(&opening_challenge);

        let r_opening = r_mod_x.evaluate(&opening_challenge);
        let q_opening = q.evaluate(&opening_challenge);

        tr.send_openings(&a_opening, &blinder_opening, &r_opening, &q_opening);

        let separation_challenge = tr.get_separation_challenge();
        let batch_opening_proof = Kzg::open(
            pk,
            &[witness.a.clone(), witness.blinder.clone(), r_mod_x, q],
            opening_challenge,
            separation_challenge,
        );

        Proof {
            r_cm: r_mod_x_cm,
            r_degree_cm,
            q_cm,
            a_opening,
            blinder_opening,
            r_opening,
            q_opening,
            batch_opening_proof,
        }
    }

    pub fn verify(
        instance: &Instance<E::G1>,
        proof: &Proof<E::G1>,
        vk: &KzgVk<E>,
        degree_check_vk: &DegreeCheckVK<E>
    ) -> Result<(), Error> {
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(instance.n).unwrap();
        let mut tr = Transcript::new(b"verifiable-folding-sumcheck");

        tr.send_instance(instance);
        tr.send_oracles(&proof.r_cm, &proof.r_degree_cm, &proof.q_cm);
        let opening_challenge = tr.get_opening_challenge();

        tr.send_openings(
            &proof.a_opening,
            &proof.blinder_opening,
            &proof.r_opening,
            &proof.q_opening,
        );
        let separation_challenge = tr.get_separation_challenge();

        let commitments = [
            instance.a_cm.clone(),
            instance.blinder_cm.clone(),
            proof.r_cm.clone(),
            proof.q_cm.clone(),
        ];

        let evaluations = [
            proof.a_opening,
            proof.blinder_opening,
            proof.r_opening,
            proof.q_opening,
        ];

        let kzg_check = Kzg::verify(
            &commitments,
            &evaluations,
            proof.batch_opening_proof,
            opening_challenge,
            separation_challenge,
            vk,
        );

        if !kzg_check.is_ok() {
            return Err(Error::OpeningFailed);
        }

        let b_evals = compute_folding_coeffs::<E::ScalarField>(&instance.challenges);
        let lagrange_evals = domain.evaluate_all_lagrange_coefficients(opening_challenge);
        let b_opening: E::ScalarField = cfg_iter!(b_evals)
            .zip(cfg_iter!(lagrange_evals))
            .map(|(&bi, &pi)| bi * pi)
            .sum();

        let lhs = proof.blinder_opening + instance.c * proof.a_opening * b_opening;

        let rhs = {
            let n_inv = E::ScalarField::from(instance.n as u64).inverse().unwrap();
            opening_challenge * proof.r_opening
                + instance.sigma * n_inv
                + proof.q_opening * domain.evaluate_vanishing_polynomial(opening_challenge)
        };

        if lhs != rhs {
            return Err(Error::RelationCheckFailed);
        }

        let shift = degree_check_vk.get_shift(instance.n - 2);
        let shift = match shift {
            Some(value) => Ok(*value),
            None => Err(Error::DegreeCheckShiftMissing),
        }?;

        let mlo = E::multi_miller_loop(&[proof.r_cm, proof.r_degree_cm], &[shift, -vk.g2]);
        let r_degree_check = E::final_exponentiation(mlo).unwrap().0;
        if r_degree_check != E::TargetField::one() {
            return Err(Error::DegreeCheckFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
mod verifiable_folding_sumcheck_tests {
    use std::{ops::Mul, collections::BTreeMap};

    use ark_bn254::{Bn254, Fr as F, G1Projective, G2Projective};
    use ark_ec::Group;
    use ark_poly::{
        univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    };
    use ark_ff::Field;
    use ark_std::{test_rng, UniformRand};
    use rand_chacha::ChaCha20Rng;

    use crate::{
        kzg::{Kzg, PK, VK, DegreeCheckVK},
        utils::{folding::compute_folding_coeffs, srs::unsafe_setup_from_tau},
    };

    use super::{
        structs::{Instance, Witness},
        Argument,
    };

    #[test]
    fn test_sumcheck() {
        let seed: [u8; 32] = [
            1, 0, 52, 0, 0, 0, 0, 0, 1, 0, 10, 0, 22, 32, 0, 0, 2, 0, 55, 49, 0, 11, 0, 0, 3, 0, 0,
            0, 0, 0, 2, 92,
        ];

        let mut rng = test_rng();
        let log_n = 4;
        let n = 1 << log_n;
        let domain = GeneralEvaluationDomain::<F>::new(n).unwrap();

        let tau = F::from(100);
        let srs = unsafe_setup_from_tau::<G1Projective>(n - 1, tau);
        let x_g2 = G2Projective::generator().mul(tau);

        // we will be checking for R <= n - 2
        let shift_factor = srs.len() - 1 - (n - 2);
        let tau_pow_shift = G2Projective::generator().mul(tau.pow(&[shift_factor as u64]));
        let mut degree_check_vk_map: BTreeMap<usize, G2Projective> = BTreeMap::new();
        degree_check_vk_map.insert(shift_factor, tau_pow_shift);
        let degree_check_vk = DegreeCheckVK::<Bn254> {
            pk_max_degree: srs.len() - 1, 
            shifts: degree_check_vk_map
        };

        let pk = PK::<Bn254> { srs: srs.clone() };
        let vk = VK::<Bn254>::new(x_g2);

        let a_coeffs: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let a_poly = DensePolynomial::from_coefficients_slice(&a_coeffs);
        let a_evals: Vec<F> = domain.fft(&a_coeffs);

        let challenges: Vec<F> = (0..log_n).map(|_| F::rand(&mut rng)).collect();

        let r = F::from(10u64);
        let c = F::from(50u64);

        let b_evals = compute_folding_coeffs(&challenges);
        let sigma: F = a_evals
            .iter()
            .zip(b_evals.iter())
            .map(|(&ai, &bi)| ai * bi)
            .sum();
        let sigma = r + c * sigma;

        // TODO: check if degree 1 is enough for blinder to preserve ZK
        let blinder = Argument::<Bn254>::sample_blinder::<ChaCha20Rng>(r, 1, n as u64, seed);

        let a_cm = Kzg::commit(&pk, &a_poly);
        let blinder_cm = Kzg::commit(&pk, &blinder);

        let instance = Instance::<G1Projective> {
            n,
            a_cm,
            c,
            sigma,
            blinder_cm,
            challenges,
        };

        let witness = Witness { a: a_poly, blinder };

        let proof = Argument::<Bn254>::prove(&instance, &witness, &pk);
        let res = Argument::<Bn254>::verify(&instance, &proof, &vk, &degree_check_vk);
        assert!(res.is_ok());
    }
}
