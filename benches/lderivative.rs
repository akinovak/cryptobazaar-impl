use std::ops::Mul;

use cipher_bazaar::kzg::{Kzg, PK, VK};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{batch_inversion, FftField, Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_bn254::{Bn254, Fr as F, G1Projective, G2Projective};
use cipher_bazaar::{
    zk_log_derivative::{
        structs::{Instance, Witness, ProverIndex, VerifierIndex},
        Argument,
    },
    utils::srs::unsafe_setup_from_tau,
};
use criterion::{criterion_group, criterion_main, Criterion};

/* RUN WITH: cargo bench --bench lderivative */

const N: usize = 8192;
const B: usize = 1;

fn prove<const N: usize, E: Pairing>(
    index_p: &ProverIndex::<E::ScalarField>,
    index_v: &VerifierIndex<E::G1>,
    instance: &Instance<E::G1>,
    witness: &Witness<E::ScalarField>,
    pk: &PK<E>,
) {
    let _ = Argument::<N, B, _>::prove(index_p, index_v, &instance, &witness, &pk);
}

fn criterion_benchmark(criterion: &mut Criterion) {
    let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();

    let tau = F::from(17u64);
    let srs = unsafe_setup_from_tau::<G1Projective>(N - 1, tau);
    let x_g2 = G2Projective::generator().mul(tau);

    let pk = PK::<Bn254> { srs: srs.clone() };
    let vk = VK::<Bn254>::new(x_g2);

    let index_v = Argument::<N, B, Bn254>::index_v(&pk);
    let index_p = Argument::<N, B, Bn254>::index_p();

    // let's make f such that it has just one 1 and 14 zeros
    let mut f_evals = vec![F::zero(); N - B];
    f_evals[3] = F::one();

    let mut blinders: Vec<_> = (0..B).map(|i| F::from((i + 10) as u64)).collect();
    let mut blinders_cloned = blinders.clone();
    f_evals.append(&mut blinders);

    let f = DensePolynomial::from_coefficients_slice(&domain.ifft(&f_evals));
    let f_cm = Kzg::commit(&pk, &f);

    let instance = Instance::<G1Projective> { f_cm };

    let witness = Witness { f };

    // RHS = 1/(beta + 1) + (N - B - 1)/(beta)
    // let relation = |beta: F| {
    //     let beta_inv = beta.inverse().unwrap();
    //     let beta_plus_one_inv = (F::one() + beta).inverse().unwrap();
    //     let n_minus_one = F::from((N - B - 1) as u64);

    //     beta_plus_one_inv + n_minus_one * beta_inv
    // };

    let id = format!("proof {}", N);
    criterion.bench_function(&id, |b| {
        b.iter(|| prove::<N, Bn254>(&index_p, &index_v, &instance, &witness, &pk))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
