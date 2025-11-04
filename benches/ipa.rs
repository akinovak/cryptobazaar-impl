use std::ops::Mul;

use ark_bn254::{Bn254, Fr as F, G1Affine, G1Projective};
use ark_ec::{pairing::Pairing, Group, VariableBaseMSM};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use cipher_bazaar::{
    ipa::{
        structs::{Instance, Witness},
        InnerProduct,
    },
    kzg::PK,
    utils::srs::unsafe_setup_from_tau,
};
use criterion::{criterion_group, criterion_main, Criterion};
use std::env;

/* RUN WITH: N={128,1024,8192} cargo bench --bench ipa */

fn prove<const N: usize, const LOG_N: usize, E: Pairing, R: RngCore>(
    instance: &Instance<N, E::G1>,
    witness: &Witness<N, E::ScalarField>,
    pk: &PK<E>,
    rng: &mut R,
) {
    InnerProduct::<N, LOG_N, E>::prove::<_>(instance, witness, pk, rng);
}

fn criterion_benchmark(criterion: &mut Criterion) {
    let n: usize = env::var("N")
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(128); // default value

    match n {
        128 => run::<128, 7>(criterion),
        1024 => run::<1024, 10>(criterion),
        8192 => run::<8192, 13>(criterion),
        _ => panic!("Unsupported instance size N"),
    }
}

fn run<const N:usize, const LOG_N: usize>(criterion: &mut Criterion) {

    let mut rng = ark_std::test_rng();
    let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();

    let tau = F::from(100u64);
    let lb_at_tau = domain.evaluate_all_lagrange_coefficients(tau);

    let srs = unsafe_setup_from_tau::<G1Projective>(N - 1, tau);
    // let x_g2 = G2Projective::generator().mul(tau);

    let pk = PK::<Bn254> { srs: srs.clone() };
    // let vk = VK::<Bn254>::new(x_g2);

    let gen = G1Projective::generator();
    let a: Vec<F> = (0..N).map(|_| F::rand(&mut rng)).collect();
    let lagrange_basis: Vec<G1Affine> = lb_at_tau.iter().map(|li| gen.mul(li).into()).collect();
    let b: Vec<G1Affine> = (0..N).map(|_| gen.mul(F::rand(&mut rng)).into()).collect();
    let h_base = gen.mul(F::rand(&mut rng));

    let ac = G1Projective::msm(&lagrange_basis, &a).unwrap();
    let c: Vec<G1Affine> = b
        .iter()
        .zip(a.iter())
        .map(|(&bi, ai)| bi.mul(ai).into())
        .collect();

    let instance = Instance::<N, G1Projective> {
        ac: ac.into(),
        b: b.try_into().unwrap(),
        h_base: h_base.into(),
        c: c.try_into().unwrap(),
    };

    let witness = Witness::<N, F> {
        a: a.try_into().unwrap(),
    };

    let id = format!("proof {}", N);
    criterion.bench_function(&id, |b| {
        b.iter(|| prove::<N, LOG_N, Bn254, _>(&instance, &witness, &pk, &mut rng))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
