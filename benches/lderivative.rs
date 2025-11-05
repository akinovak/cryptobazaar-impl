use cipher_bazaar::kzg::{Kzg, PK};
use ark_ec::{pairing::Pairing};
use ark_ff::{One, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain
};
use ark_bn254::{Bn254, Fr as F, G1Projective};
use cipher_bazaar::{
    zk_log_derivative::{
        structs::{Instance, Witness, ProverIndex, VerifierIndex},
        Argument,
    },
    utils::srs::unsafe_setup_from_tau,
};
use criterion::{criterion_group, criterion_main, Criterion};
use std::env;

/* RUN WITH: N={128,1024,8192} cargo bench --bench lderivative */

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
    let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();
    let tau = F::from(17u64);
    let srs = unsafe_setup_from_tau::<G1Projective>(N - 1, tau);
    let pk = PK::<Bn254> { srs: srs.clone() };
    let index_v = Argument::<N, B, Bn254>::index_v(&pk);
    let index_p = Argument::<N, B, Bn254>::index_p();

    // let's make f such that it has just one 1 and 14 zeros
    let mut f_evals = vec![F::zero(); N - B];
    f_evals[3] = F::one();
    let mut blinders: Vec<_> = (0..B).map(|i| F::from((i + 10) as u64)).collect();
    f_evals.append(&mut blinders);
    let f = DensePolynomial::from_coefficients_slice(&domain.ifft(&f_evals));
    let f_cm = Kzg::commit(&pk, &f);

    let instance = Instance::<G1Projective> { f_cm };
    let witness = Witness { f };

    let id = format!(r"proof \pi_{{b_i}} N={}", N);
    criterion.bench_function(&id, |b| {
        b.iter(|| prove::<N, Bn254>(&index_p, &index_v, &instance, &witness, &pk))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
