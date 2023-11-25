/*
    All gates exist over q_price(X) which is selector that is 1 on |p| - price range entires
    gate1: q_price(X)(r(X) * r_inv(X) - 1) = 0 mod zH(X)
    gate2: q_price(X)(g(X) - f(X) - bid(X)*r(X)) = 0 mod zH(X)
    gate3: q_price(X)(diff(X) - bid(X) + bid(wX)) = 0 mod zH(X)
    gate4: L_(p+1)(X)bid(X) = 0 mod zH(X)

    degree of quotient will be n - 1 + n - 1 + n - 1 - n = 3n - 3 - n = 2n - 3, so we can work with subgroup of 2n
*/

use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::{batch_inversion, FftField, Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};

use crate::{
    kzg::{Kzg, PK as KzgPk, VK as KzgVk},
    utils::{evaluate_vanishing_over_extended_coset, powers_of_x},
};

use self::{
    structs::{Oracle, Proof, ProverIndex, VerifierIndex, Witness},
    tr::Transcript,
};

pub mod structs;
mod tr;

impl<'a, F: Field> Oracle<'a, F> {
    pub fn query(&self, i: usize, rotation: usize) -> F {
        self.0[(i + rotation) & self.0.len()]
    }
}

pub struct GatesArgument<const N: usize, const P: usize, E: Pairing> {
    _e: PhantomData<E>,
}

impl<const N: usize, const P: usize, E: Pairing> GatesArgument<N, P, E> {
    fn make_q_price() -> DensePolynomial<E::ScalarField> {
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(N).unwrap();

        let (n, p) = (N, P);
        let mut q_price_evals = vec![E::ScalarField::one(); p];
        let mut zeros = vec![E::ScalarField::zero(); n - p];
        q_price_evals.append(&mut zeros);

        DensePolynomial::from_coefficients_slice(&domain.ifft(&q_price_evals))
    }

    pub fn verifier_index(pk: &KzgPk<E>) -> VerifierIndex<E::G1> {
        let q_price = Self::make_q_price();
        let q_price_cm = Kzg::commit(pk, &q_price);
        VerifierIndex { q_price_cm }
    }

    pub fn prover_index() -> ProverIndex<E::ScalarField> {
        let domain_n = GeneralEvaluationDomain::<E::ScalarField>::new(N).unwrap();
        let domain_2n = GeneralEvaluationDomain::<E::ScalarField>::new(2 * N).unwrap();
        let coset_2n_domain = domain_2n.get_coset(E::ScalarField::GENERATOR).unwrap();

        let q_price = Self::make_q_price();
        let q_price_coset_evals = coset_2n_domain.fft(&q_price);

        let mut l_p_next_evals = vec![E::ScalarField::zero(); N];
        l_p_next_evals[P + 1] = E::ScalarField::one();

        let l_p_next = domain_n.ifft(&l_p_next_evals);
        let l_p_next_coset_evals = coset_2n_domain.fft(&l_p_next);

        ProverIndex {
            q_price,
            q_price_coset_evals,
            l_p_next_coset_evals,
        }
    }

    pub fn prove(
        witness: &Witness<E::ScalarField>,
        v_index: &VerifierIndex<E::G1>, // just to hash
        index: &ProverIndex<E::ScalarField>,
        pk: &KzgPk<E>,
    ) -> Proof<E::G1> {
        let k = 2;
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(N).unwrap();
        let domain_kn = GeneralEvaluationDomain::<E::ScalarField>::new(k * N).unwrap();
        let coset_kn_domain = domain_kn.get_coset(E::ScalarField::GENERATOR).unwrap();

        let mut tr = Transcript::<E::G1>::new(b"gates-transcript");
        tr.send_index(v_index);

        let bid_cm = Kzg::commit(pk, &witness.bid);
        let f_cm = Kzg::commit(pk, &witness.f);
        let r_cm = Kzg::commit(pk, &witness.r);
        let r_inv_cm = Kzg::commit(pk, &witness.r_inv);
        let diff_cm = Kzg::commit(pk, &witness.diff);
        let g_cm = Kzg::commit(pk, &witness.g);

        tr.send_oracle_commitments(&bid_cm, &f_cm, &r_cm, &r_inv_cm, &diff_cm, &g_cm);
        let alpha = tr.get_quotient_challenge();
        let alpha_pows = powers_of_x(alpha, 4);

        let bid_coset_evals = coset_kn_domain.fft(&witness.bid);
        let bid_coset_evals = Oracle(&bid_coset_evals);

        let f_coset_evals = coset_kn_domain.fft(&witness.f);
        let f_coset_evals = Oracle(&f_coset_evals);

        let r_coset_evals = coset_kn_domain.fft(&witness.r);
        let r_coset_evals = Oracle(&r_coset_evals);

        let r_inv_coset_evals = coset_kn_domain.fft(&witness.r_inv);
        let r_inv_coset_evals = Oracle(&r_inv_coset_evals);

        let diff_coset_evals = coset_kn_domain.fft(&witness.diff);
        let diff_coset_evals = Oracle(&diff_coset_evals);

        let g_coset_evals = coset_kn_domain.fft(&witness.g);
        let g_coset_evals = Oracle(&g_coset_evals);

        let q_price_coset_evals = Oracle(&index.q_price_coset_evals);
        let l_p_next_coset_evals = Oracle(&index.l_p_next_coset_evals);

        let mut modulus_zh_coset_evals =
            evaluate_vanishing_over_extended_coset::<E::ScalarField>(N, k);
        batch_inversion(&mut modulus_zh_coset_evals);

        let mut q_coset_evals = vec![E::ScalarField::zero(); k * N];
        let one = E::ScalarField::one();

        for i in 0..(k * N) {
            let q_price_i = q_price_coset_evals.query(i, 0);
            let bid_i = bid_coset_evals.query(i, 0);
            let bid_i_next = bid_coset_evals.query(i, 1);
            let r_i = r_coset_evals.query(i, 0);
            let r_inv_i = r_inv_coset_evals.query(i, 0);
            let f_i = f_coset_evals.query(i, 0);
            let diff_i = diff_coset_evals.query(i, 0);
            let g_i = g_coset_evals.query(i, 0);
            let l_p_next_coset_evals_i = l_p_next_coset_evals.query(i, 0);

            // gate1
            q_coset_evals[i] = alpha_pows[0] * q_price_i * (r_i * r_inv_i - one);

            // gate2
            q_coset_evals[i] += alpha_pows[1] * q_price_i * (g_i - f_i - bid_i * r_i);

            // gate3
            q_coset_evals[i] += alpha_pows[2] * q_price_i * (diff_i - bid_i + bid_i_next);

            // gate4
            q_coset_evals[i] += alpha_pows[3] * l_p_next_coset_evals_i * bid_i;

            // rescale by zh_inv
            let zh_inv_i = modulus_zh_coset_evals[i % k];
            q_coset_evals[i] *= zh_inv_i
        }

        let q = coset_kn_domain.ifft(&q_coset_evals);

        // hardcoded to 2 chunks
        let q_chunk_0 = DensePolynomial::from_coefficients_slice(&q[..N]);
        let q_chunk_1 = DensePolynomial::from_coefficients_slice(&q[N..]);

        let q_chunk_0_cm = Kzg::commit(pk, &q_chunk_0);
        let q_chunk_1_cm = Kzg::commit(pk, &q_chunk_1);

        tr.send_q_chunks(&q_chunk_0_cm, &q_chunk_1_cm);

        // open everything
        let gamma = tr.get_evaluation_challenge();

        let q_price_opening = index.q_price.evaluate(&gamma);
        let bid_opening = witness.bid.evaluate(&gamma);
        let bid_shift_opening = witness.bid.evaluate(&(gamma * domain.element(1)));
        let f_opening = witness.f.evaluate(&gamma);
        let r_opening = witness.r.evaluate(&gamma);
        let r_inv_opening = witness.r_inv.evaluate(&gamma);
        let diff_opening = witness.diff.evaluate(&gamma);
        let g_opening = witness.g.evaluate(&gamma);
        let q_chunk_0_opening = q_chunk_0.evaluate(&gamma);
        let q_chunk_1_opening = q_chunk_1.evaluate(&gamma);

        tr.send_oracle_openings(
            &q_price_opening,
            &bid_opening,
            &bid_shift_opening,
            &f_opening,
            &r_opening,
            &r_inv_opening,
            &diff_opening,
            &g_opening,
            &q_chunk_0_opening,
            &q_chunk_1_opening,
        );

        let separation_challenge = tr.get_separation_challenge();

        let w_0 = Kzg::open(
            pk,
            &[
                index.q_price.clone(),
                witness.bid.clone(),
                witness.f.clone(),
                witness.r.clone(),
                witness.r_inv.clone(),
                witness.diff.clone(),
                witness.g.clone(),
                q_chunk_0.clone(),
                q_chunk_1.clone(),
            ],
            gamma,
            separation_challenge,
        );

        let w_1 = Kzg::open(pk, &[witness.bid.clone()], gamma * domain.element(1), one);

        Proof {
            bid_cm,
            r_cm,
            r_inv_cm,
            f_cm,
            diff_cm,
            g_cm,
            q_price_opening,
            bid_opening,
            bid_shift_opening,
            f_opening,
            r_opening,
            r_inv_opening,
            diff_opening,
            g_opening,
            q_chunk_0_cm,
            q_chunk_1_cm,
            q_chunk_0_opening,
            q_chunk_1_opening,
            w_0,
            w_1,
        }
    }

    pub fn verify(index: &VerifierIndex<E::G1>, proof: &Proof<E::G1>, vk: &KzgVk<E>) {
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(N).unwrap();
        let mut tr = Transcript::<E::G1>::new(b"gates-transcript");
        tr.send_index(index);

        tr.send_oracle_commitments(
            &proof.bid_cm,
            &proof.f_cm,
            &proof.r_cm,
            &proof.r_inv_cm,
            &proof.diff_cm,
            &proof.g_cm,
        );
        let alpha = tr.get_quotient_challenge();
        let alpha_pows = powers_of_x(alpha, 4);

        tr.send_q_chunks(&proof.q_chunk_0_cm, &proof.q_chunk_1_cm);
        let gamma = tr.get_evaluation_challenge();

        tr.send_oracle_openings(
            &proof.q_price_opening,
            &proof.bid_opening,
            &proof.bid_shift_opening,
            &proof.f_opening,
            &proof.r_opening,
            &proof.r_inv_opening,
            &proof.diff_opening,
            &proof.g_opening,
            &proof.q_chunk_0_opening,
            &proof.q_chunk_1_opening,
        );

        let separation_challenge = tr.get_separation_challenge();

        let res_gamma = Kzg::verify(
            &[proof.bid_cm],
            &[proof.bid_shift_opening],
            proof.w_0,
            gamma,
            separation_challenge,
            vk,
        );

        assert!(res_gamma.is_ok());

        let res_gamma_sh = Kzg::verify(
            &[
                index.q_price_cm,
                proof.bid_cm,
                proof.f_cm,
                proof.r_cm,
                proof.r_inv_cm,
                proof.diff_cm,
                proof.g_cm,
                proof.q_chunk_0_cm,
                proof.q_chunk_1_cm,
            ],
            &[
                proof.q_price_opening,
                proof.bid_opening,
                proof.f_opening,
                proof.r_opening,
                proof.r_inv_opening,
                proof.diff_opening,
                proof.g_opening,
                proof.q_chunk_0_opening,
                proof.q_chunk_1_opening,
            ],
            proof.w_1,
            gamma * domain.element(1),
            E::ScalarField::one(),
            vk,
        );

        assert!(res_gamma_sh.is_ok());

        let zh_at_gamma = domain.evaluate_vanishing_polynomial(gamma);
        let l_p_next_at_gamma = {
            let n_inv = domain.size_as_field_element().inverse().unwrap();
            let w_p_next = domain.element(P + 1);

            let x_minus_w_p_next_inv = (gamma - w_p_next).inverse().unwrap();

            w_p_next * n_inv * zh_at_gamma * x_minus_w_p_next_inv
        };

        let gamma_pow_n = gamma.pow(&[N as u64]);

        let lhs = {
            let g1 = alpha_pows[0]
                * proof.q_price_opening
                * (proof.r_opening * proof.r_inv_opening - E::ScalarField::one());
            let g2 = alpha_pows[1]
                * proof.q_price_opening
                * (proof.g_opening - proof.f_opening - proof.bid_opening * proof.r_opening);
            let g3 = alpha_pows[2]
                * proof.q_price_opening
                * (proof.diff_opening - proof.bid_opening + proof.bid_shift_opening);
            let g4 = alpha_pows[3] * l_p_next_at_gamma * proof.bid_opening;

            g1 + g2 + g3 + g4
        };

        let rhs =
            { (proof.q_chunk_0_opening + gamma_pow_n * proof.q_chunk_1_opening) * zh_at_gamma };

        if lhs != rhs {
            panic!("Relation check failed")
        }
    }
}
