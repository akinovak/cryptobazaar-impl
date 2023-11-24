use ark_ff::FftField;
use ark_poly::{GeneralEvaluationDomain, EvaluationDomain};

pub mod folding;
pub mod srs;

pub fn is_pow_2(x: usize) -> bool {
    (x & (x - 1)) == 0
}

pub fn powers_of_x<F: FftField>(x: F, n: usize) -> Vec<F> {
    std::iter::successors(Some(F::one()), |p| Some(*p * x))
        .take(n)
        .collect()
}

pub fn evaluate_vanishing_over_extended_coset<F: FftField>(n: usize, k: usize) -> Vec<F> {
    assert!(is_pow_2(n));
    assert!(is_pow_2(k));

    let domain_kn = GeneralEvaluationDomain::<F>::new(k * n).unwrap();

    let coset_generator_pow_n = F::GENERATOR.pow(&[n as u64]);
    let wi = domain_kn.element(1);

    let mut modulus_zh_coset_evals = Vec::with_capacity(k);

    for i in 0usize..k {
        let zhi = coset_generator_pow_n * wi.pow(&[(i * n) as u64]) - F::one();
        modulus_zh_coset_evals.push(zhi);
    }

    modulus_zh_coset_evals
}

#[cfg(test)]
mod util_tests {
    use ark_bn254::Fr as F;
    use ark_ff::FftField;
    use ark_poly::{GeneralEvaluationDomain, EvaluationDomain, univariate::DensePolynomial, Polynomial};

    use crate::utils::evaluate_vanishing_over_extended_coset; 

    #[test]
    fn test_domain() {
        let n = 16; 
        let k = 4;

        let domain = GeneralEvaluationDomain::<F>::new(n).unwrap();
        let domain_kn = GeneralEvaluationDomain::<F>::new(k * n).unwrap();
        let coset_kn = domain_kn.get_coset(F::GENERATOR).unwrap();

        let zh: DensePolynomial<_> = domain.vanishing_polynomial().into();
        let zh_evals: Vec<_> = coset_kn.elements().map(|wi| zh.evaluate(&wi)).collect();

        let modulus_zh_coset_evals = evaluate_vanishing_over_extended_coset::<F>(n, k);

        for i in 0..(k * n) {
            let idx = i % k;
            assert_eq!(zh_evals[i], modulus_zh_coset_evals[idx]);
        }
    }
}
