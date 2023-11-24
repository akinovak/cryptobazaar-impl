use std::ops::Mul;

use ark_ec::Group;
use ark_std::{test_rng, cfg_iter};
use ark_bn254::{Fr as F, G1Projective as G1};
use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/* RUN WITH: cargo bench --bench encode */


fn encode(x: &[F], gen: &G1) -> Vec<G1> {
    cfg_iter!(x).map(|xi| gen.mul(xi)).collect()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = test_rng(); 
    let g = G1::generator();

    let n_logs = [7, 10, 13];
    for n_logi in n_logs {
        let n = 1 << n_logi;
        let x: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();

        let id = format!("encode {}", n);
        c.bench_function(&id, |b| b.iter(|| encode(&x, &g)));
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);