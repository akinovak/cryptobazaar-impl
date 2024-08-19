use std::ops::Mul;

use cipher_bazaar::kzg::{Kzg, PK, VK};
use ark_ec::{pairing::Pairing, Group, ScalarMul};
use ark_ff::{batch_inversion, FftField, Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_bn254::{Bn254, Fr as F, G1Affine, G1Projective, G2Projective};
use cipher_bazaar::{
    utils::srs::unsafe_setup_from_tau,
};
use criterion::{criterion_group, criterion_main, Criterion};
use ark_std::UniformRand;

/* RUN WITH: cargo bench --bench nonzero */

const N: usize = 8192;

fn criterion_benchmark(criterion: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();

    let tau = F::from(17u64);
    let srs = unsafe_setup_from_tau::<G1Projective>(N - 1, tau);
    let x_g2 = G2Projective::generator().mul(tau);

    let pk = PK::<Bn254> { srs: srs.clone() };
    let vk = VK::<Bn254>::new(x_g2);

    let x: Vec<F> = (0..N).map(|_| F::rand(&mut rng)).collect();
    let x_poly: DensePolynomial<_> = DensePolynomial::from_coefficients_slice(&domain.ifft(&x));

    // let a_cm = Kzg::commit(&pk, &x_poly);
    // let gamma = F::rand(&mut rng);
    // let one = F::from(1u64);
    // let g1 = G1Projective::generator();
    // let x_vec: Vec<G1Affine> = x.iter().map(|xi| g1.mul(xi).into()).collect();

    let id = format!("proof {}", N);
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
