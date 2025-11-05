use std::ops::Mul;
use ark_ec::{Group};
use ark_bn254::{Fr as F, G1Projective};
use criterion::{criterion_group, criterion_main, Criterion};
use ark_std::UniformRand;
use std::env;

/* RUN WITH: N={128,1024,8192} cargo bench --bench veceq */

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
    let x: Vec<F> = (0..N).map(|_| F::rand(&mut rng)).collect();
    let g1 = G1Projective::generator();
    let id = format!(r"proof \pi_{{x_i}} N={}", N);
    criterion.bench_function(&id, |b| {
        b.iter(|| {
            let _x_vec: Vec<G1Projective> = x.iter().map(|xi| g1.mul(xi).into()).collect();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
