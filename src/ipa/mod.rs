use std::marker::PhantomData;
use std::ops::Mul;

use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_std::UniformRand;
use rand::RngCore;

use crate::kzg::{DegreeCheckVK, PK as KzgPk, VK as KzgVk};
use crate::utils::folding::{compute_folding_coeffs, AffFold, FFold, Fold};
use crate::utils::powers_of_x;
use crate::verifiable_folding_sumcheck::{
    structs::{Error as VFSError, Instance as VFSInstance, Witness as VFSWitness},
    Argument as VFSArgument,
};

use self::structs::{Instance, Proof, Witness};
use self::tr::Transcript;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub mod structs;
mod tr;

pub struct InnerProduct<const N: usize, const LOG_N: usize, E: Pairing> {
    _e: PhantomData<E>,
}

impl<const N: usize, const LOG_N: usize, E: Pairing> InnerProduct<N, LOG_N, E> {
    pub fn prove<R: RngCore>(
        instance: &Instance<N, E::G1>,
        witness: &Witness<N, E::ScalarField>,
        pk: &KzgPk<E>,
        rng: &mut R,
    ) -> Proof<LOG_N, E::G1> {
        #[cfg(feature = "parallel")]
        let num_chunks = rayon::current_num_threads();
        #[cfg(not(feature = "parallel"))]
        let num_chunks = 1;

        let mut acc_blinders = E::ScalarField::zero();

        let mut l_msgs = Vec::<E::G1Affine>::with_capacity(LOG_N);
        let mut r_msgs = Vec::<E::G1Affine>::with_capacity(LOG_N);

        let mut alphas = Vec::with_capacity(LOG_N);

        let mut tr = Transcript::<N, LOG_N, _>::new(b"ipa");
        tr.send_instance(instance);

        let r = tr.get_r();
        let r_pows = powers_of_x(r, N);

        // let mut c_fold: E::G1 = instance.ac.clone().into();
        let mut c_fold = E::G1::msm(&instance.c, &r_pows).unwrap();

        let mut a_folded = witness.a.clone().to_vec();
        let b_folded: Vec<E::G1> = instance
            .b
            .iter()
            .zip(r_pows.iter())
            .map(|(&bi, ri)| bi.mul(ri))
            .collect();
        let mut b_folded: Vec<E::G1Affine> = E::G1::normalize_batch(&b_folded);

        for _ in 0..LOG_N as usize {
            let a_left = &a_folded[..a_folded.len() / 2];
            let a_right = &a_folded[a_folded.len() / 2..];

            let b_left = &b_folded[..b_folded.len() / 2];
            let b_right = &b_folded[b_folded.len() / 2..];

            let chunk_size = if num_chunks <= a_left.len() {
                a_left.len() / num_chunks
            } else {
                1
            };

            #[cfg(feature = "parallel")]
            let (a_left_chunks, b_right_chunks) = (
                a_left.par_chunks(chunk_size),
                b_right.par_chunks(chunk_size),
            );
            #[cfg(feature = "parallel")]
            let (a_right_chunks, b_left_chunks) = (
                a_right.par_chunks(chunk_size),
                b_left.par_chunks(chunk_size),
            );

            #[cfg(not(feature = "parallel"))]
            let (a_left_chunks, b1_right_chunks) =
                (x_left.chunks(chunk_size), b_right.chunks(chunk_size));
            #[cfg(not(feature = "parallel"))]
            let (a_right_chunks, b1_left_chunks) =
                (x_right.chunks(chunk_size), b_left.chunks(chunk_size));

            let l: E::G1 = a_left_chunks
                .zip(b_right_chunks)
                .map(|(ali, bri)| E::G1::msm(bri, ali).unwrap())
                .sum();
            let r: E::G1 = a_right_chunks
                .zip(b_left_chunks)
                .map(|(ari, bli)| E::G1::msm(bli, ari).unwrap())
                .sum();

            let blinder_l = E::ScalarField::rand(rng);
            let blinder_r = E::ScalarField::rand(rng);

            let l: E::G1Affine = (l + instance.h_base.mul(&blinder_l)).into();
            l_msgs.push(l);

            let r: E::G1Affine = (r + instance.h_base.mul(&blinder_r)).into();
            r_msgs.push(r);

            tr.send_l_r(&l, &r);
            let alpha = tr.get_alpha_i();
            let alpha_inv = alpha.inverse().unwrap();
            alphas.push(alpha);

            acc_blinders += alpha_inv * blinder_l + alpha * blinder_r;

            // fold vectors
            a_folded = FFold::fold_vec(&a_folded, alpha).unwrap();
            b_folded = AffFold::fold_vec(&b_folded, alpha_inv).unwrap();

            // derive new cm
            c_fold = l.mul(alpha_inv) + c_fold + r.mul(alpha);
        }

        // sanity
        {
            assert_eq!(b_folded.len(), 1);
            assert_eq!(a_folded.len(), 1);

            let lhs = b_folded[0].mul(a_folded[0]) + instance.h_base.mul(&acc_blinders);

            assert_eq!(lhs, c_fold);
        }

        let vfs_instance = VFSInstance::<E::G1> {
            n: N,
            p_base: b_folded[0],
            h_base: instance.h_base,
            a_cm: instance.ac,
            pedersen: c_fold.into(),
            challenges: alphas.try_into().unwrap(),
        };

        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(N).unwrap();
        let a = DensePolynomial::from_coefficients_slice(&domain.ifft(&witness.a));
        let vfs_witness = VFSWitness {
            a,
            x: a_folded[0],
            r: acc_blinders,
        };

        {
            let x = b_folded[0].mul(a_folded[0]) + instance.h_base.mul(acc_blinders);
            assert_eq!(x, c_fold);
        }

        let vfs_proof = VFSArgument::<E>::prove(&vfs_instance, &vfs_witness, pk, rng);

        Proof {
            l: l_msgs.try_into().unwrap(),
            r: r_msgs.try_into().unwrap(),
            vfs_proof,
        }
    }

    pub fn verify(
        instance: &Instance<N, E::G1>,
        proof: &Proof<LOG_N, E::G1>,
        vk: &KzgVk<E>,
        degree_check_vk: &DegreeCheckVK<E>,
    ) -> Result<(), VFSError> {
        let mut tr = Transcript::<N, LOG_N, _>::new(b"ipa");
        tr.send_instance(instance);

        let r = tr.get_r();
        let r_pows = powers_of_x(r, N);

        let mut c_fold = E::G1::msm(&instance.c, &r_pows).unwrap();

        let b_rescaled: Vec<E::G1> = instance
            .b
            .iter()
            .zip(r_pows.iter())
            .map(|(&bi, ri)| bi.mul(ri))
            .collect();
        let b_rescaled: Vec<E::G1Affine> = E::G1::normalize_batch(&b_rescaled);

        let mut alphas = Vec::with_capacity(LOG_N);
        let mut alpha_invs = Vec::with_capacity(LOG_N);

        for i in 0..LOG_N as usize {
            tr.send_l_r(&proof.l[i], &proof.r[i]);

            let alpha = tr.get_alpha_i();
            let alpha_inv = alpha.inverse().unwrap();
            alphas.push(alpha);
            alpha_invs.push(alpha_inv);

            c_fold = proof.l[i].mul(alpha_inv) + c_fold + proof.r[i].mul(alpha);
        }

        // now fold the basis b and check pedersen openings
        let fold_coeffs = compute_folding_coeffs::<E::ScalarField>(&alpha_invs);
        let b_folded = E::G1::msm(&b_rescaled, &fold_coeffs).unwrap();

        let vfs_instance = VFSInstance::<E::G1> {
            n: N,
            p_base: b_folded.into(),
            h_base: instance.h_base,
            a_cm: instance.ac,
            pedersen: c_fold.into(),
            challenges: alphas.try_into().unwrap(),
        };

        VFSArgument::<E>::verify(&vfs_instance, &proof.vfs_proof, vk, degree_check_vk)?;
        Ok(())
    }
}

#[cfg(test)]
mod ipa_tests {
    use std::{collections::BTreeMap, ops::Mul};

    use ark_bn254::{Bn254, Fr as F, G1Affine, G1Projective, G2Projective};
    use ark_ec::{Group, VariableBaseMSM};
    use ark_ff::Field;
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_std::UniformRand;

    use crate::{
        kzg::{DegreeCheckVK, PK, VK},
        utils::srs::unsafe_setup_from_tau,
    };

    use super::{
        structs::{Instance, Witness},
        InnerProduct,
    };

    const N: usize = 32;
    const LOG_N: usize = 5;

    #[test]
    fn test_ipa() {
        let mut rng = ark_std::test_rng();
        let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();

        let tau = F::from(100u64);
        let lb_at_tau = domain.evaluate_all_lagrange_coefficients(tau);

        let srs = unsafe_setup_from_tau::<G1Projective>(N - 1, tau);
        let x_g2 = G2Projective::generator().mul(tau);

        let pk = PK::<Bn254> { srs: srs.clone() };
        let vk = VK::<Bn254>::new(x_g2);

        // we will be checking for R <= n - 2
        let shift_factor = srs.len() - 1 - (N - 2);
        let tau_pow_shift = G2Projective::generator().mul(tau.pow(&[shift_factor as u64]));
        let mut degree_check_vk_map: BTreeMap<usize, G2Projective> = BTreeMap::new();
        degree_check_vk_map.insert(shift_factor, tau_pow_shift);
        let degree_check_vk = DegreeCheckVK::<Bn254> {
            pk_max_degree: srs.len() - 1,
            shifts: degree_check_vk_map,
        };

        let gen = G1Projective::generator();
        let a: Vec<F> = (0..N).map(|_| F::rand(&mut rng)).collect();
        let lagrange_basis: Vec<G1Affine> = lb_at_tau.iter().map(|li| gen.mul(li).into()).collect();
        let b: Vec<G1Affine> = (0..N).map(|_| gen.mul(F::rand(&mut rng)).into()).collect();
        let h_base = gen.mul(F::rand(&mut rng));

        let ac = G1Projective::msm(&lagrange_basis, &a).unwrap();
        let c: Vec<G1Affine> = b
            .iter()
            .zip(a.iter())
            .map(|(&bi, ai)| bi.mul(ai).into())
            .collect();

        let instance = Instance::<N, G1Projective> {
            ac: ac.into(),
            b: b.try_into().unwrap(),
            h_base: h_base.into(),
            c: c.try_into().unwrap(),
        };

        let witness = Witness::<N, F> {
            a: a.try_into().unwrap(),
        };

        let proof = InnerProduct::<N, LOG_N, Bn254>::prove::<_>(&instance, &witness, &pk, &mut rng);
        let res = InnerProduct::<N, LOG_N, Bn254>::verify(&instance, &proof, &vk, &degree_check_vk);
        assert!(res.is_ok());
    }
}
