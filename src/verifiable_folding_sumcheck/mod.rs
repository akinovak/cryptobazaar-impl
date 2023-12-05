use std::marker::PhantomData;
use std::ops::Mul;

use ark_ec::pairing::Pairing;
use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
};
use ark_std::{cfg_iter, UniformRand};
use rand::RngCore;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use self::structs::{Error, Instance, Proof, Witness};
use crate::{
    kzg::{DegreeCheckVK, Kzg, PK as KzgPk, VK as KzgVk},
    utils::{folding::compute_folding_coeffs, is_pow_2},
    verifiable_folding_sumcheck::tr::Transcript,
};

pub mod structs;
mod tr;

pub struct Argument<E: Pairing> {
    _e: PhantomData<E>,
}

impl<E: Pairing> Argument<E> {
    pub fn sample_blinder<R: RngCore>(
        sum: E::ScalarField,
        degree: usize,
        n: u64,
        rng: &mut R,
    ) -> DensePolynomial<E::ScalarField> {
        let mut blinder = DensePolynomial::<E::ScalarField>::rand(degree, rng);

        let n_inv = E::ScalarField::from(n).inverse().unwrap();
        blinder[0] = sum * n_inv;

        blinder
    }

    pub fn prove<R: RngCore>(
        instance: &Instance<E::G1>,
        witness: &Witness<E::ScalarField>,
        pk: &KzgPk<E>,
        rng: &mut R,
    ) -> Proof<E::G1> {
        assert!(is_pow_2(instance.n));
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(instance.n).unwrap();
        let mut tr = Transcript::new(b"verifiable-folding-sumcheck");

        tr.send_instance(instance);

        let (b_1, b_2) = (E::ScalarField::rand(rng), E::ScalarField::rand(rng));
        let s = (instance.p_base.mul(&b_1) + instance.h_base.mul(&b_2)).into();

        // TODO: check if degree 1 is enough for blinder to preserve ZK
        let blinder = Self::sample_blinder::<_>(b_1, 1, instance.n as u64, rng);
        let blinder_cm = Kzg::commit(pk, &blinder);
        tr.send_blinders(&s, &blinder_cm);

        let c = tr.get_c();

        let z_1 = c * witness.x + b_1;
        let z_2 = c * witness.r + b_2;

        let b_evals = compute_folding_coeffs::<E::ScalarField>(&instance.challenges);
        let b: DensePolynomial<<E as Pairing>::ScalarField> =
            DensePolynomial::from_coefficients_slice(&domain.ifft(&b_evals));

        // B(X) + ca(X)b(X)
        let lhs = &blinder + &(&(&witness.a * &b) * c);

        let (q, r) = DenseOrSparsePolynomial::from(lhs.clone())
            .divide_with_q_and_r(&domain.vanishing_polynomial().into())
            .unwrap();
        assert_eq!(z_1, E::ScalarField::from(instance.n as u64) * r[0]);
        let r_mod_x = DensePolynomial::from_coefficients_slice(&r.coeffs[1..]);

        // // deg(r_mod_x) <= n - 2
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

        tr.second_round(&z_1, &z_2, &r_mod_x_cm, &r_degree_cm, &q_cm);
        let opening_challenge = tr.get_opening_challenge();

        let a_opening = witness.a.evaluate(&opening_challenge);
        let blinder_opening = blinder.evaluate(&opening_challenge);

        let r_opening = r_mod_x.evaluate(&opening_challenge);
        let q_opening = q.evaluate(&opening_challenge);

        tr.send_openings(&a_opening, &blinder_opening, &r_opening, &q_opening);

        let separation_challenge = tr.get_separation_challenge();
        let batch_opening_proof = Kzg::open(
            pk,
            &[witness.a.clone(), blinder.clone(), r_mod_x, q],
            opening_challenge,
            separation_challenge,
        );

        Proof {
            // round 1
            s,
            blinder_cm,

            // round 2
            z_1,
            z_2,
            r_cm: r_mod_x_cm,
            r_degree_cm,
            q_cm,

            // round 3
            a_opening,
            blinder_opening,
            r_opening,
            q_opening,

            // round 4
            batch_opening_proof,
        }
    }

    pub fn verify(
        instance: &Instance<E::G1>,
        proof: &Proof<E::G1>,
        vk: &KzgVk<E>,
        degree_check_vk: &DegreeCheckVK<E>,
    ) -> Result<(), Error> {
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(instance.n).unwrap();
        let mut tr = Transcript::new(b"verifiable-folding-sumcheck");

        tr.send_instance(instance);
        tr.send_blinders(&proof.s, &proof.blinder_cm);
        let c = tr.get_c();

        tr.second_round(
            &proof.z_1,
            &proof.z_2,
            &proof.r_cm,
            &proof.r_degree_cm,
            &proof.q_cm,
        );
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
            proof.blinder_cm.clone(),
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

        let eq = {
            instance.pedersen.mul(c) + proof.s
                == instance.p_base.mul(proof.z_1) + instance.h_base.mul(proof.z_2)
        };

        if !eq {
            return Err(Error::PedersenOpeningFailed);
        }

        let b_evals = compute_folding_coeffs::<E::ScalarField>(&instance.challenges);
        let lagrange_evals = domain.evaluate_all_lagrange_coefficients(opening_challenge);
        let b_opening: E::ScalarField = cfg_iter!(b_evals)
            .zip(cfg_iter!(lagrange_evals))
            .map(|(&bi, &pi)| bi * pi)
            .sum();

        let lhs = proof.blinder_opening + c * proof.a_opening * b_opening;

        let rhs = {
            let n_inv = E::ScalarField::from(instance.n as u64).inverse().unwrap();
            opening_challenge * proof.r_opening
                + proof.z_1 * n_inv
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
    use std::{collections::BTreeMap, ops::Mul};

    use ark_bn254::{Bn254, Fr as F, G1Affine, G1Projective, G2Projective};
    use ark_ec::Group;
    use ark_ff::Field;
    use ark_poly::{
        univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    };
    use ark_std::{test_rng, UniformRand};

    use crate::{
        kzg::{DegreeCheckVK, Kzg, PK, VK},
        utils::{folding::compute_folding_coeffs, srs::unsafe_setup_from_tau},
    };

    use super::{
        structs::{Instance, Witness},
        Argument,
    };

    #[test]
    fn test_sumcheck() {
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
            shifts: degree_check_vk_map,
        };

        let pk = PK::<Bn254> { srs: srs.clone() };
        let vk = VK::<Bn254>::new(x_g2);

        let a_coeffs: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
        let a_poly = DensePolynomial::from_coefficients_slice(&a_coeffs);
        let a_evals: Vec<F> = domain.fft(&a_coeffs);

        let challenges: Vec<F> = (0..log_n).map(|_| F::rand(&mut rng)).collect();

        let g = G1Projective::generator();
        let p = F::from(200u64);
        let h = F::from(300u64);

        let p_base: G1Affine = g.mul(&p).into();
        let h_base: G1Affine = g.mul(&h).into();

        let r = F::from(10u64);
        // let c = F::from(50u64);

        let b_evals = compute_folding_coeffs(&challenges);
        let x: F = a_evals
            .iter()
            .zip(b_evals.iter())
            .map(|(&ai, &bi)| ai * bi)
            .sum();

        let pedersen = p_base.mul(x) + h_base.mul(r);

        let a_cm = Kzg::commit(&pk, &a_poly);

        let instance = Instance::<G1Projective> {
            n,
            p_base,
            h_base,
            a_cm,
            pedersen: pedersen.into(),
            challenges,
        };

        let witness = Witness { a: a_poly, r, x };

        let proof = Argument::<Bn254>::prove(&instance, &witness, &pk, &mut rng);
        let res = Argument::<Bn254>::verify(&instance, &proof, &vk, &degree_check_vk);
        assert!(res.is_ok());
    }
}
