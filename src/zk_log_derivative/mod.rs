/*
    Given f(X) over domain of size N where b last evaluations are blinders
    we want to prove some log derivative relation "R(X)" about first N - b evaluations

    In other words: "prove that ∑1/(ß + f_i) = R(ß)"

    Both prover and verifier run indexer which computes s(X) such that
    s = [1, 1, ..., 0, 0, 0] (all 1 and then 0 last N - b evaluations)

    1. Prover sends ¥, which is claimed to be inverse blinders sum, ¥ = ∑1/fi for i in [N - b, N]
    2. Verifiers sends ß and computes R(ß)
    3. Prover sends b(X) and q(X)
    4. Verifier sends µ
    5. Prover sends b(0), b(µ), q(µ), f(µ), s(µ)
    6. Verifier sends separation challenge ¡
    7. Prover sends kzg proofs [πs]
    6. Verifier checks
        1. [πs]
        2. b(µ)(ß * s(µ) + f(µ)) - 1 = q(µ)zH(µ)
        3. b(0) = (R(ß) + ¥)/N
*/

use crate::kzg::{Kzg, PK as KzgPk, VK as KzgVk};
use ark_ec::pairing::Pairing;
use ark_ff::{batch_inversion, FftField, Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_std::cfg_iter;
use std::marker::PhantomData;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use self::{
    structs::{Error, Instance, Proof, ProverIndex, VerifierIndex, Witness},
    tr::Transcript,
};

pub mod structs;
mod tr;

pub struct Argument<const N: usize, const B: usize, E: Pairing> {
    _e: PhantomData<E>,
}

impl<const N: usize, const B: usize, E: Pairing> Argument<N, B, E> {
    pub fn index_v(pk: &KzgPk<E>) -> VerifierIndex<E::G1> {
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(N).unwrap();
        let mut zeros = vec![E::ScalarField::zero(); B];
        let mut s_evals = vec![E::ScalarField::one(); N - B];

        s_evals.append(&mut zeros);
        let s = DensePolynomial::from_coefficients_slice(&domain.ifft(&s_evals));
        let s_cm = Kzg::commit(pk, &s);

        VerifierIndex { s_cm: s_cm.into() }
    }

    pub fn index_p() -> ProverIndex<E::ScalarField> {
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(N).unwrap();
        let coset_domain = domain.get_coset(E::ScalarField::GENERATOR).unwrap();

        let mut zeros = vec![E::ScalarField::zero(); B];
        let mut s_evals = vec![E::ScalarField::one(); N - B];

        s_evals.append(&mut zeros);
        let s_coeffs = &domain.ifft(&s_evals);

        ProverIndex {
            s: DensePolynomial::from_coefficients_slice(&s_coeffs),
            s_coset_evals: coset_domain.fft(&s_coeffs),
        }
    }

    // TODO: make more memory optimal function by using fft in place
    pub fn prove(
        index: &ProverIndex<E::ScalarField>,
        v_index: &VerifierIndex<E::G1>, // needed for tr hashing
        instance: &Instance<E::G1>,
        witness: &Witness<E::ScalarField>,
        pk: &KzgPk<E>,
    ) -> Proof<E::G1> {
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(N).unwrap();
        let coset_domain = domain.get_coset(E::ScalarField::GENERATOR).unwrap();

        let f_evals = domain.fft(&witness.f);
        let f_coset_evals = coset_domain.fft(&witness.f);

        let mut tr = Transcript::new(b"log-derivative");
        tr.send_v_index(v_index);
        tr.send_instance(instance);

        let mut blinders = f_evals[N - B..].to_vec();
        batch_inversion(&mut blinders);
        let gamma: E::ScalarField = blinders.iter().sum();

        tr.send_blinders_sum(&gamma);
        let beta = tr.get_beta();

        let mut b_evals: Vec<_> = cfg_iter!(f_evals)
            .take(N - B)
            .map(|&f_i| f_i + beta)
            .collect();
        batch_inversion(&mut b_evals);
        b_evals.append(&mut blinders);

        let b = DensePolynomial::from_coefficients_slice(&domain.ifft(&b_evals));
        let b_cm = Kzg::commit(pk, &b);
        let b_coset_evals = coset_domain.fft(&b);

        let zh_coset_inv = domain
            .evaluate_vanishing_polynomial(E::ScalarField::GENERATOR)
            .inverse()
            .unwrap();

        let q_coset_evals: Vec<_> = cfg_iter!(b_coset_evals)
            .zip(cfg_iter!(f_coset_evals))
            .zip(cfg_iter!(index.s_coset_evals))
            .map(|((&b_i, f_i), &s_i)| {
                (b_i * (s_i * beta + f_i) - E::ScalarField::one()) * zh_coset_inv
            })
            .collect();

        let q = DensePolynomial::from_coefficients_slice(&coset_domain.ifft(&q_coset_evals));
        let q_cm = Kzg::commit(pk, &q);

        tr.send_b_and_q(&b_cm, &q_cm);
        let mu = tr.get_mu();

        let f_opening = witness.f.evaluate(&mu);
        let s_opening = index.s.evaluate(&mu);
        let b_opening_zero = b.evaluate(&E::ScalarField::zero());
        let b_opening = b.evaluate(&mu);
        let q_opening = q.evaluate(&mu);

        tr.send_openings(
            &f_opening,
            &s_opening,
            &b_opening_zero,
            &b_opening,
            &q_opening,
        );
        let separation_challenge = tr.get_separation_challenge();

        let q_0 = &b
            / &DensePolynomial::from_coefficients_slice(&[
                E::ScalarField::zero(),
                E::ScalarField::one(),
            ]);
        let q_0 = Kzg::commit(pk, &q_0);
        let q_1 = Kzg::open(
            pk,
            &[witness.f.clone(), index.s.clone(), b, q],
            mu,
            separation_challenge,
        );

        Proof {
            gamma,
            b_cm,
            q_cm,
            f_opening,
            s_opening,
            b_opening_zero,
            b_opening,
            q_opening,
            q_0,
            q_1,
        }
    }

    pub fn verify<Func>(
        index: &VerifierIndex<E::G1>,
        instance: &Instance<E::G1>,
        proof: &Proof<E::G1>,
        vk: &KzgVk<E>,
        relation: &Func,
    ) -> Result<(), Error>
    where
        Func: Fn(E::ScalarField) -> E::ScalarField,
    {
        let mut tr = Transcript::new(b"log-derivative");
        tr.send_v_index(index);
        tr.send_instance(instance);

        tr.send_blinders_sum(&proof.gamma);
        let beta = tr.get_beta();
        let relation_at_beta = relation(beta);

        tr.send_b_and_q(&proof.b_cm, &proof.q_cm);
        let mu = tr.get_mu();

        tr.send_openings(
            &proof.f_opening,
            &proof.s_opening,
            &proof.b_opening_zero,
            &proof.b_opening,
            &proof.q_opening,
        );
        let separation_challenge = tr.get_separation_challenge();

        Kzg::verify(
            &[proof.b_cm],
            &[proof.b_opening_zero],
            proof.q_0,
            E::ScalarField::zero(),
            E::ScalarField::one(),
            vk,
        )
        .unwrap();
        Kzg::verify(
            &[instance.f_cm, index.s_cm, proof.b_cm, proof.q_cm],
            &[
                proof.f_opening,
                proof.s_opening,
                proof.b_opening,
                proof.q_opening,
            ],
            proof.q_1,
            mu,
            separation_challenge,
            vk,
        )
        .unwrap();

        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(N).unwrap();
        let formation_eq = {
            let zh_eval = domain.evaluate_vanishing_polynomial(mu);
            proof.b_opening * (beta * proof.s_opening + proof.f_opening) - E::ScalarField::one()
                == proof.q_opening * zh_eval
        };

        let sumcheck_eq = {
            let n_inv = domain.size_as_field_element().inverse().unwrap();
            proof.b_opening_zero == (relation_at_beta + proof.gamma) * n_inv
        };

        Ok(())
    }
}
