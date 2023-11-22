use ark_ec::CurveGroup;
use ark_ff::{FftField, Field};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};

use crate::utils::is_pow_2;

pub fn compute_lagrange_basis_commitments<C: CurveGroup>(tau_powers: &[C]) -> Vec<C::Affine> {
    let n = tau_powers.len();
    assert!(is_pow_2(n));

    let domain = GeneralEvaluationDomain::<C::ScalarField>::new(n).unwrap();
    let n_inv = domain.size_as_field_element().inverse().unwrap();

    let p_evals: Vec<C> = domain.fft(&tau_powers);
    let p_evals_reversed = std::iter::once(p_evals[0]).chain(p_evals.into_iter().skip(1).rev());

    let ls: Vec<C> = p_evals_reversed
        .into_iter()
        .map(|pi| pi.mul(n_inv))
        .collect();

    C::normalize_batch(&ls)
}

pub fn construct_lagrange_basis<F: FftField>(evaluation_domain: &[F]) -> Vec<DensePolynomial<F>> {
    let mut bases = Vec::with_capacity(evaluation_domain.len());
    for i in 0..evaluation_domain.len() {
        let mut l_i = DensePolynomial::from_coefficients_slice(&[F::one()]);
        let x_i = evaluation_domain[i];
        for (j, _) in evaluation_domain.iter().enumerate() {
            if j != i {
                let xi_minus_xj_inv = (x_i - evaluation_domain[j]).inverse().unwrap();
                l_i = &l_i
                    * &DensePolynomial::from_coefficients_slice(&[
                        -evaluation_domain[j] * xi_minus_xj_inv,
                        xi_minus_xj_inv,
                    ]);
            }
        }

        bases.push(l_i);
    }

    bases
}

#[cfg(test)]
mod lagrange_test {
    use ark_bn254::{Fr, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, CurveGroup, Group};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};
    use std::ops::Mul;

    use crate::{
        kzg::lagrange::{compute_lagrange_basis_commitments, construct_lagrange_basis},
        utils::srs::unsafe_setup_from_tau,
    };

    #[test]
    fn test_lagrange() {
        let n: usize = 16;
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        let roots: Vec<Fr> = domain.elements().collect();

        let lb = construct_lagrange_basis(&roots);

        let tau = Fr::from(19);
        let srs = unsafe_setup_from_tau::<G1Projective>(n - 1, tau);

        let lb_commitments_from_tau: Vec<G1Projective> = lb
            .iter()
            .map(|li| G1Projective::generator().mul(li.evaluate(&tau)))
            .collect();
        let lb_commitments_from_tau: Vec<G1Affine> =
            G1Projective::normalize_batch(&lb_commitments_from_tau);

        let srs_projective: Vec<G1Projective> = srs.iter().map(|c| c.into_group()).collect();
        let lb_commitments = compute_lagrange_basis_commitments(&srs_projective);

        assert_eq!(lb_commitments_from_tau, lb_commitments);
    }
}
