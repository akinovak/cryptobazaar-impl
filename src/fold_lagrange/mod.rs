/*
    1. P sends [p] claimed to be correct folding of lagrange basis commitments given array of challenges {ch}
    2. V sends ß
    3. P
        1. computes a(X) = ∑ß^iLi(X)
        2. sends [a] and π (well formation proof of a)

    4: P, V
        Run univariate sumcheck to prove that ∑p_i * a_i = fold(ß)
*/

use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::One;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};
use std::marker::PhantomData;

use self::structs::{Error, Proof};
use self::{structs::Instance, tr::Transcript};
use crate::acc::{
    structs::{Instance as AccInstance, Witness as AccWitness},
    Argument as AccArgument,
};
use crate::univariate_sumcheck::structs::{Instance as UVInstance, Witness as UVWitness};
use crate::univariate_sumcheck::UnivariateSumcheck;
use crate::{
    kzg::{Kzg, PK as KzgPk, VK as KzgVk},
    utils::folding::compute_folding_coeffs,
};

pub mod structs;
mod tr;

// TODO: finish accumulation well formation proof
pub struct Argument<const N: usize, const LOG_N: usize, E: Pairing> {
    _c: PhantomData<E>,
}

impl<const N: usize, const LOG_N: usize, E: Pairing> Argument<N, LOG_N, E> {
    pub fn prove(pk: &KzgPk<E>, instance: &Instance<N, LOG_N, E::G1>) -> Proof<E::G1> {
        let mut tr = Transcript::<E::G1>::new(b"fold-lagrange");
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(N).unwrap();

        let folding_coeffs = compute_folding_coeffs(&instance.challenges);

        let p_cm = (E::G1::msm(&instance.lb_commitments, &folding_coeffs).unwrap()).into();

        tr.send_p(&p_cm);
        let beta = tr.get_beta();

        let beta_powers: Vec<E::ScalarField> =
            std::iter::successors(Some(E::ScalarField::one()), |p| Some(*p * beta))
                .take(N)
                .collect();

        let sum = folding_coeffs
            .iter()
            .zip(beta_powers.iter())
            .map(|(&f_i, &beta_i)| f_i * beta_i)
            .sum::<E::ScalarField>();

        let p = DensePolynomial::from_coefficients_slice(&domain.ifft(&folding_coeffs));
        let acc = DensePolynomial::from_coefficients_slice(&domain.ifft(&beta_powers));

        let acc_cm = Kzg::commit(pk, &acc);

        /*** Sumcheck */
        let uv_instance = UVInstance::<E::G1> {
            n: N,
            a_cm: p_cm.clone(),
            b_cm: acc_cm.clone(),
            sum,
        };

        let uv_witness = UVWitness {
            a_poly: p,
            b_poly: acc.clone(),
        };

        let sumcheck_proof = UnivariateSumcheck::<E>::prove(&uv_witness, &uv_instance, pk);
        /*** Sumcheck */

        /*** Acc */
        let acc_instance = AccInstance {
            n: N,
            mu: beta,
            acc_cm,
        };

        let acc_witness = AccWitness { acc };

        let acc_proof = AccArgument::prove(&acc_instance, &acc_witness, pk);

        /*** Acc */

        Proof {
            p_cm,
            acc_cm,
            acc_proof,
            sumcheck_proof,
        }
    }

    pub fn verify(
        proof: &Proof<E::G1>,
        instance: &Instance<N, LOG_N, E::G1>,
        vk: &KzgVk<E>,
    ) -> Result<(), Error> {
        let mut tr = Transcript::<E::G1>::new(b"fold-lagrange");
        let folding_coeffs = compute_folding_coeffs(&instance.challenges);

        tr.send_p(&proof.p_cm);
        let beta = tr.get_beta();

        let acc_instance = AccInstance::<E::G1> {
            n: N,
            mu: beta,
            acc_cm: proof.acc_cm,
        };

        let beta_powers: Vec<E::ScalarField> =
            std::iter::successors(Some(E::ScalarField::one()), |p| Some(*p * beta))
                .take(N)
                .collect();

        let sum = folding_coeffs
            .iter()
            .zip(beta_powers.iter())
            .map(|(&f_i, &beta_i)| f_i * beta_i)
            .sum::<E::ScalarField>();

        let uv_instance = UVInstance::<E::G1> {
            n: N,
            a_cm: proof.p_cm,
            b_cm: proof.acc_cm,
            sum,
        };

        UnivariateSumcheck::<E>::verify(&proof.sumcheck_proof, &uv_instance, vk)?;
        AccArgument::<E>::verify(&acc_instance, &proof.acc_proof, vk)?;
        Ok(())
    }
}

#[cfg(test)]
mod lagrange_fold_tests {
    use ark_bn254::{Bn254, Fr as F, G1Projective, G2Projective};
    use ark_ec::{CurveGroup, Group};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use std::ops::Mul;

    use crate::{
        kzg::{PK, VK},
        utils::srs::unsafe_setup_from_tau,
    };

    use super::{structs::Instance, Argument};

    const N: usize = 16;
    const LOG_N: usize = 4;

    #[test]
    fn test_folding() {
        let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();
        let g = G1Projective::generator();

        let toxic_waste = F::from(17u64);
        let srs = unsafe_setup_from_tau::<G1Projective>(N - 1, toxic_waste);
        let x_g2 = G2Projective::generator().mul(toxic_waste);

        let pk = PK::<Bn254> { srs: srs.clone() };
        let vk = VK::<Bn254>::new(x_g2);

        let lb_at_tw = domain.evaluate_all_lagrange_coefficients(toxic_waste);

        let lb_commitments: Vec<_> = lb_at_tw.iter().map(|li| g.mul(li)).collect();
        let lb_commitments = G1Projective::normalize_batch(&lb_commitments);

        let chs: Vec<_> = (0..LOG_N).map(|i| F::from((10 + i) as u64)).collect();

        let instance = Instance::<N, LOG_N, G1Projective> {
            lb_commitments: lb_commitments.try_into().unwrap(),
            challenges: chs.try_into().unwrap(),
        };

        let proof = Argument::prove(&pk, &instance);
        let res = Argument::verify(&proof, &instance, &vk);
        assert!(res.is_ok());
    }
}
