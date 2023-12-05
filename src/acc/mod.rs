/*
    Given µ, Argument shows that acc(X) evaluations are powers of µ, ex. (1, µ, µ^2, µ^3)

    1. P sends [acc] and q (note that because of degrees it's just a field element)
    2. V samples ß
    3. P sends (q_0, 1), (q_ß, acc(ß)), (q_wß, acc(wß))
    4. V checks:
        1. all kzg opening proofs
        2. (acc(wß) - µ*acc(ß))(ß - w^(n-1)) = q * zH(ß)
*/

use crate::kzg::{Kzg, PK as KzgPk, VK as KzgVk};
use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field, One};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use std::marker::PhantomData;

use self::{
    structs::{Error, Instance, Proof, Witness},
    tr::Transcript,
};

pub mod structs;
mod tr;

pub struct Argument<E: Pairing> {
    _e: PhantomData<E>,
}

impl<E: Pairing> Argument<E> {
    pub fn prove(
        instance: &Instance<E::G1>,
        witness: &Witness<E::ScalarField>,
        pk: &KzgPk<E>,
    ) -> Proof<E::G1> {
        let mut tr = Transcript::new(b"acc-transcript");
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(instance.n).unwrap();
        // since q is degree 0 we can compute it in any point that is not root of unity

        tr.send_instance(instance);

        let p = E::ScalarField::GENERATOR;
        let acc_sh = witness.acc.evaluate(&(p * domain.element(1)));
        let acc = witness.acc.evaluate(&p);
        let zh_eval = domain.evaluate_vanishing_polynomial(p);

        let q = {
            let lhs = (acc_sh - instance.mu * acc) * (p - domain.element(instance.n - 1));
            lhs * zh_eval.inverse().unwrap()
        };

        tr.send_q(&q);
        let beta = tr.get_beta();

        let q_0 = &witness.acc
            / &DensePolynomial::from_coefficients_slice(&[
                -E::ScalarField::one(),
                E::ScalarField::one(),
            ]);
        let q_0 = Kzg::commit(pk, &q_0);

        let q_1 = &witness.acc
            / &DensePolynomial::from_coefficients_slice(&[-beta, E::ScalarField::one()]);
        let q_1 = Kzg::commit(pk, &q_1);

        let q_2 = &witness.acc
            / &DensePolynomial::from_coefficients_slice(&[
                -(beta * domain.element(1)),
                E::ScalarField::one(),
            ]);
        let q_2 = Kzg::commit(pk, &q_2);

        Proof {
            q,
            acc_opening: witness.acc.evaluate(&beta),
            acc_shifted_opening: witness.acc.evaluate(&(beta * domain.element(1))),
            q_0,
            q_1,
            q_2,
        }
    }

    pub fn verify(
        instance: &Instance<E::G1>,
        proof: &Proof<E::G1>,
        vk: &KzgVk<E>,
    ) -> Result<(), Error> {
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(instance.n).unwrap();
        let mut tr = Transcript::new(b"acc-transcript");
        tr.send_instance(instance);
        tr.send_q(&proof.q);
        let beta = tr.get_beta();

        // When integrated with more complex proofs this part will be merged with some multiopen argument
        let one = E::ScalarField::one();
        let kzg_at_one = Kzg::verify(
            &[instance.acc_cm],
            &[one.clone()],
            proof.q_0,
            one.clone(),
            one.clone(),
            vk,
        );

        if !kzg_at_one.is_ok() {
            return Err(Error::OpeningFailed);
        }

        let kzg_at_beta = Kzg::verify(
            &[instance.acc_cm],
            &[proof.acc_opening],
            proof.q_1,
            beta,
            one.clone(),
            vk,
        );

        if !kzg_at_beta.is_ok() {
            return Err(Error::OpeningFailed);
        }

        let kzg_at_beta_sh = Kzg::verify(
            &[instance.acc_cm],
            &[proof.acc_shifted_opening],
            proof.q_2,
            beta * domain.element(1),
            one.clone(),
            vk,
        );

        if !kzg_at_beta_sh.is_ok() {
            return Err(Error::OpeningFailed);
        }

        let zh_eval = domain.evaluate_vanishing_polynomial(beta);
        let eq = {
            (proof.acc_shifted_opening - instance.mu * proof.acc_opening)
                * (beta - domain.element(instance.n - 1))
                == proof.q * zh_eval
        };

        if !eq {
            return Err(Error::RelationCheck);
        }

        Ok(())
    }
}

#[cfg(test)]
mod acc_tests {
    use ark_bn254::{Bn254, Fr as F, G1Projective, G2Projective};
    use ark_ec::Group;
    use ark_ff::One;
    use ark_poly::{
        univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    };
    use std::ops::Mul;

    use crate::{
        kzg::{Kzg, PK, VK},
        utils::srs::unsafe_setup_from_tau,
    };

    use super::{
        structs::{Instance, Witness},
        Argument,
    };
    #[test]
    fn test_acc() {
        let n = 16;
        let domain = GeneralEvaluationDomain::<F>::new(n).unwrap();

        let tau = F::from(17u64);
        let srs = unsafe_setup_from_tau::<G1Projective>(n - 1, tau);
        let x_g2 = G2Projective::generator().mul(tau);

        let pk = PK::<Bn254> { srs: srs.clone() };
        let vk = VK::<Bn254>::new(x_g2);

        let mu = F::from(100u64);
        let powers_of_mu: Vec<_> = std::iter::successors(Some(F::one()), |p| Some(*p * mu))
            .take(n)
            .collect();

        let acc = DensePolynomial::from_coefficients_slice(&domain.ifft(&powers_of_mu));
        let acc_cm = Kzg::commit(&pk, &acc);

        let instance = Instance::<G1Projective> { n, mu, acc_cm };
        let witness = Witness { acc };

        let proof = Argument::prove(&instance, &witness, &pk);
        let result = Argument::verify(&instance, &proof, &vk);
        assert!(result.is_ok());
    }
}
