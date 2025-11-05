use cipher_bazaar::kzg::{Kzg, PK};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};
use ark_bn254::{Bn254, Fr as F, G1Projective};
use cipher_bazaar::{
    utils::srs::unsafe_setup_from_tau,
};
use criterion::{criterion_group, criterion_main, Criterion};
use ark_std::UniformRand;
use std::env;

/* RUN WITH: N={128,1024,8192} cargo bench --bench nonzero */

fn criterion_benchmark(criterion: &mut Criterion) {
    let n: usize = env::var("N")
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(128); // default value

    match n {
        128 => run::<128>(criterion),
        1024 => run::<1024>(criterion),
        8192 => run::<8192>(criterion),
        _ => panic!("Unsupported price range N"),
    }
}

fn run<const N:usize>(criterion: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();
    let tau = F::from(17u64);
    let srs = unsafe_setup_from_tau::<G1Projective>(N - 1, tau);
    let pk = PK::<Bn254> { srs: srs.clone() };
    let id = format!(r"proof \pi_{{r_i}} N={}", N);
    criterion.bench_function(&id, |b| {
        b.iter(|| {
            /*
                commit to r, 
                commit to r_inv, 
                r_ifft 
                r_coset_fft 
                r_inv_ifft 
                r_inv_coset_fft 
                q_ifft 
                commit to q 
                commit to quotient for kzg opening 

                so we can just bench 5 ffts and 4 kzg commits to get realistic bench
             */
            let x: Vec<F> = (0..N).map(|_| F::rand(&mut rng)).collect();
            let x_poly: DensePolynomial<_> = DensePolynomial::from_coefficients_slice(&domain.ifft(&x));
            let _ = Kzg::commit(&pk, &x_poly);

            let x: Vec<F> = (0..N).map(|_| F::rand(&mut rng)).collect();
            let x_poly: DensePolynomial<_> = DensePolynomial::from_coefficients_slice(&domain.ifft(&x));
            let _ = Kzg::commit(&pk, &x_poly);

            let x: Vec<F> = (0..N).map(|_| F::rand(&mut rng)).collect();
            let x_poly: DensePolynomial<_> = DensePolynomial::from_coefficients_slice(&domain.ifft(&x));
            let _ = Kzg::commit(&pk, &x_poly);

            let x: Vec<F> = (0..N).map(|_| F::rand(&mut rng)).collect();
            let x_poly: DensePolynomial<_> = DensePolynomial::from_coefficients_slice(&domain.ifft(&x));
            let _ = Kzg::commit(&pk, &x_poly);

            let x: Vec<F> = (0..N).map(|_| F::rand(&mut rng)).collect();
            let _: DensePolynomial<_> = DensePolynomial::from_coefficients_slice(&domain.ifft(&x));
        })
    });

}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
