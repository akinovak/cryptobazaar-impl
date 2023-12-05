use std::{marker::PhantomData, ops::Mul};

use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, Zero};
use ark_std::{cfg_iter, rand::RngCore, UniformRand};

use crate::double_pedersen_schnorr::{
    structs::{Instance as PSInstance, Witness as PSWitness},
    Argument as PSArgument,
};
use crate::fold_lagrange::{structs::Instance as LFInstance, Argument as LFArgument};
use crate::kzg::{PK as KzgPk, VK as KzgVk};
use crate::utils::folding::compute_folding_coeffs;
use crate::utils::{is_pow_2, powers_of_x};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use self::{
    structs::{Instance, Proof, Witness},
    tr::Transcript,
};

pub mod structs;
mod tr;

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

pub struct DoubleInnerProduct<const N: usize, const LOG_N: usize, E: Pairing> {
    _e: PhantomData<E>,
}

impl<const N: usize, const LOG_N: usize, E: Pairing> DoubleInnerProduct<N, LOG_N, E> {
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

        let mut acc_blinders_1 = E::ScalarField::zero();
        let mut acc_blinders_2 = E::ScalarField::zero();

        let mut l_1_msgs = Vec::<E::G1Affine>::with_capacity(LOG_N);
        let mut l_2_msgs = Vec::<E::G1Affine>::with_capacity(LOG_N);
        let mut r_1_msgs = Vec::<E::G1Affine>::with_capacity(LOG_N);
        let mut r_2_msgs = Vec::<E::G1Affine>::with_capacity(LOG_N);

        let mut alpha_invs = Vec::with_capacity(LOG_N);

        let mut tr = Transcript::<N, LOG_N, _>::new(b"double-ipa");
        tr.send_instance(instance);

        let r = tr.get_r();
        let r_pows = powers_of_x(r, N);

        let mut c1_fold: E::G1 = instance.ac.clone().into();
        let mut c2_fold = E::G1::msm(&instance.c, &r_pows).unwrap();

        let mut a_folded = witness.a.clone().to_vec();
        let mut b1_folded = instance.lagrange_basis.clone().to_vec();
        let b2_folded: Vec<E::G1> = instance
            .b
            .iter()
            .zip(r_pows.iter())
            .map(|(&bi, ri)| bi.mul(ri))
            .collect();
        let mut b2_folded: Vec<E::G1Affine> = E::G1::normalize_batch(&b2_folded);

        for _ in 0..LOG_N as usize {
            let a_left = &a_folded[..a_folded.len() / 2];
            let a_right = &a_folded[a_folded.len() / 2..];

            let b1_left = &b1_folded[..b1_folded.len() / 2];
            let b1_right = &b1_folded[b1_folded.len() / 2..];

            let b2_left = &b2_folded[..b2_folded.len() / 2];
            let b2_right = &b2_folded[b2_folded.len() / 2..];

            let chunk_size = if num_chunks <= a_left.len() {
                a_left.len() / num_chunks
            } else {
                1
            };

            #[cfg(feature = "parallel")]
            let (x_left_chunks, b1_right_chunks, b2_right_chunks) = (
                a_left.par_chunks(chunk_size),
                b1_right.par_chunks(chunk_size),
                b2_right.par_chunks(chunk_size),
            );
            #[cfg(feature = "parallel")]
            let (x_right_chunks, b1_left_chunks, b2_left_chunks) = (
                a_right.par_chunks(chunk_size),
                b1_left.par_chunks(chunk_size),
                b2_left.par_chunks(chunk_size),
            );

            #[cfg(not(feature = "parallel"))]
            let (x_left_chunks, b1_right_chunks, b2_right_chunks) = (
                x_left.chunks(chunk_size),
                b1_right.chunks(chunk_size),
                b2_right.chunks(chunk_size),
            );
            #[cfg(not(feature = "parallel"))]
            let (x_right_chunks, b1_left_chunks, b2_left_chunks) = (
                x_right.chunks(chunk_size),
                b1_left.chunks(chunk_size),
                b2_left.chunks(chunk_size),
            );

            let l_1: E::G1 = x_left_chunks
                .clone()
                .zip(b1_right_chunks)
                .map(|(xli, bri)| E::G1::msm(bri, xli).unwrap())
                .sum();
            let r_1: E::G1 = x_right_chunks
                .clone()
                .zip(b1_left_chunks)
                .map(|(xli, bri)| E::G1::msm(bri, xli).unwrap())
                .sum();

            let l_2: E::G1 = x_left_chunks
                .zip(b2_right_chunks)
                .map(|(xli, bri)| E::G1::msm(bri, xli).unwrap())
                .sum();
            let r_2: E::G1 = x_right_chunks
                .zip(b2_left_chunks)
                .map(|(xli, bri)| E::G1::msm(bri, xli).unwrap())
                .sum();

            let blinder_l1 = E::ScalarField::rand(rng);
            let blinder_r1 = E::ScalarField::rand(rng);

            let blinder_l2 = E::ScalarField::rand(rng);
            let blinder_r2 = E::ScalarField::rand(rng);

            let l_1: E::G1Affine = (l_1 + instance.h_base.mul(&blinder_l1)).into();
            l_1_msgs.push(l_1);

            let r_1: E::G1Affine = (r_1 + instance.h_base.mul(&blinder_r1)).into();
            r_1_msgs.push(r_1);

            let l_2: E::G1Affine = (l_2 + instance.h_base.mul(&blinder_l2)).into();
            l_2_msgs.push(l_2);

            let r_2: E::G1Affine = (r_2 + instance.h_base.mul(&blinder_r2)).into();
            r_2_msgs.push(r_2);

            tr.send_ls_rs(&l_1, &r_1, &l_2, &r_2);
            let alpha = tr.get_alpha_i();
            let alpha_inv = alpha.inverse().unwrap();
            alpha_invs.push(alpha_inv);

            acc_blinders_1 += alpha_inv * blinder_l1 + alpha * blinder_r1;
            acc_blinders_2 += alpha_inv * blinder_l2 + alpha * blinder_r2;

            // fold vectors
            a_folded = FFold::fold_vec(&a_folded, alpha).unwrap();
            b1_folded = AffFold::fold_vec(&b1_folded, alpha_inv).unwrap();
            b2_folded = AffFold::fold_vec(&b2_folded, alpha_inv).unwrap();

            // derive new cm
            c1_fold = l_1.mul(alpha_inv) + c1_fold + r_1.mul(alpha);
            c2_fold = l_2.mul(alpha_inv) + c2_fold + r_2.mul(alpha);
        }

        // sanity
        {
            assert_eq!(b1_folded.len(), 1);
            assert_eq!(b2_folded.len(), 1);

            assert_eq!(a_folded.len(), 1);

            let lhs_1 = b1_folded[0].mul(a_folded[0]) + instance.h_base.mul(&acc_blinders_1);
            let lhs_2 = b2_folded[0].mul(a_folded[0]) + instance.h_base.mul(&acc_blinders_2);

            assert_eq!(lhs_1, c1_fold);
            assert_eq!(lhs_2, c2_fold);
        }

        let ps_instance = PSInstance::<E::G1> {
            q_base: b1_folded[0],
            p_base: b2_folded[0],
            h_base: instance.h_base,
            x_1: c1_fold.into(),
            x_2: c2_fold.into(),
        };

        let ps_witness = PSWitness {
            a: a_folded[0],
            r_1: acc_blinders_1,
            r_2: acc_blinders_2,
        };

        let ps_proof = PSArgument::prove(&ps_instance, &ps_witness, rng);

        let lf_instance = LFInstance::<N, LOG_N, E::G1> {
            lb_commitments: instance.lagrange_basis,
            challenges: alpha_invs.try_into().unwrap(),
        };

        let lf_proof = LFArgument::prove(pk, &lf_instance);

        Proof::<LOG_N, E::G1> {
            l_1: l_1_msgs.try_into().unwrap(),
            r_1: r_1_msgs.try_into().unwrap(),
            l_2: l_2_msgs.try_into().unwrap(),
            r_2: r_2_msgs.try_into().unwrap(),
            lf_proof,
            ps_proof,
        }
    }

    pub fn verify(instance: &Instance<N, E::G1>, proof: &Proof<LOG_N, E::G1>, vk: &KzgVk<E>) {
        let mut tr = Transcript::<N, LOG_N, _>::new(b"double-ipa");
        tr.send_instance(instance);

        let r = tr.get_r();
        let r_pows = powers_of_x(r, N);

        let mut c1_fold: E::G1 = instance.ac.clone().into();
        let mut c2_fold = E::G1::msm(&instance.c, &r_pows).unwrap();

        let b2_rescaled: Vec<E::G1> = instance
            .b
            .iter()
            .zip(r_pows.iter())
            .map(|(&bi, ri)| bi.mul(ri))
            .collect();
        let b2_rescaled: Vec<E::G1Affine> = E::G1::normalize_batch(&b2_rescaled);

        let mut alpha_invs = Vec::with_capacity(LOG_N);

        for i in 0..LOG_N as usize {
            tr.send_ls_rs(&proof.l_1[i], &proof.r_1[i], &proof.l_2[i], &proof.r_2[i]);

            let alpha = tr.get_alpha_i();
            let alpha_inv = alpha.inverse().unwrap();
            alpha_invs.push(alpha_inv);

            c1_fold = proof.l_1[i].mul(alpha_inv) + c1_fold + proof.r_1[i].mul(alpha);
            c2_fold = proof.l_2[i].mul(alpha_inv) + c2_fold + proof.r_2[i].mul(alpha);
        }

        // now fold the basis b and check pedersen openings
        let fold_coeffs = compute_folding_coeffs::<E::ScalarField>(&alpha_invs);
        let b2_folded = E::G1::msm(&b2_rescaled, &fold_coeffs).unwrap();

        let lf_instance = LFInstance::<N, LOG_N, E::G1> {
            lb_commitments: instance.lagrange_basis,
            challenges: alpha_invs.try_into().unwrap(),
        };

        let lf_folding_res = LFArgument::verify(&proof.lf_proof, &lf_instance, vk);
        assert!(lf_folding_res.is_ok());

        let ps_instance = PSInstance::<E::G1> {
            q_base: proof.lf_proof.p_cm,
            p_base: b2_folded.into(),
            h_base: instance.h_base,
            x_1: c1_fold.into(),
            x_2: c2_fold.into(),
        };

        let res = PSArgument::verify(&ps_instance, &proof.ps_proof);
        assert!(res.is_ok());
    }
}

#[cfg(test)]
mod double_ipa_tests {
    use std::ops::Mul;

    use ark_bn254::{Bn254, Fr as F, G1Affine, G1Projective, G2Projective};
    use ark_ec::{Group, VariableBaseMSM};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_std::UniformRand;

    use crate::{
        kzg::{PK, VK},
        utils::srs::unsafe_setup_from_tau,
    };

    use super::{
        structs::{Instance, Witness},
        DoubleInnerProduct,
    };

    const N: usize = 32;
    const LOG_N: usize = 5;

    #[test]
    fn test_double_ipa() {
        let mut rng = ark_std::test_rng();
        let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();

        let tau = F::from(100u64);
        let lb_at_tau = domain.evaluate_all_lagrange_coefficients(tau);

        let srs = unsafe_setup_from_tau::<G1Projective>(N - 1, tau);
        let x_g2 = G2Projective::generator().mul(tau);

        let pk = PK::<Bn254> { srs: srs.clone() };
        let vk = VK::<Bn254>::new(x_g2);

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
            lagrange_basis: lagrange_basis.try_into().unwrap(),
            b: b.try_into().unwrap(),
            h_base: h_base.into(),
            c: c.try_into().unwrap(),
        };

        let witness = Witness::<N, F> {
            a: a.try_into().unwrap(),
        };

        let proof =
            DoubleInnerProduct::<N, LOG_N, Bn254>::prove::<_>(&instance, &witness, &pk, &mut rng);
        DoubleInnerProduct::<N, LOG_N, Bn254>::verify(&instance, &proof, &vk);
    }
}
