use std::ops::Mul;

use ark_bn254::{Fr as F, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_ff::Zero;
use ark_std::{test_rng, UniformRand};
use cipher_bazaar::auctioneer::Auctioneer;
use criterion::{criterion_group, criterion_main, Criterion};
use std::env;

/* RUN WITH: M=32 N=1024 cargo bench --bench auctioneer_r2 */

fn setup_round_1<const N: usize, const B: usize>() -> Auctioneer<N, B, G1Projective> {
    let mut rng = test_rng();
    let g = G1Projective::generator();

    let mut a = Auctioneer::<N, B, G1Projective>::new();
    let mut secrets = vec![vec![F::zero(); N]; B];
    let mut first_msgs = vec![vec![G1Affine::zero(); N]; B];

    // initialize n msgs fro each party
    for i in 0..B {
        for j in 0..N {
            secrets[i][j] = F::rand(&mut rng);
        }
    }

    // initialize n msgs fro each party
    for i in 0..B {
        for j in 0..N {
            first_msgs[i][j] = g.mul(secrets[i][j]).into();
        }
    }

    // each party sends it's first round msgs
    for i in 0..B {
        a.register_msgs(&first_msgs[i], i).unwrap();
    }

    a
}

fn setup_round_2<const N: usize, const B: usize>() -> Auctioneer<N, B, G1Projective> {
    let mut rng = test_rng();
    let g = G1Projective::generator();

    let mut a = Auctioneer::<N, B, G1Projective>::new();
    let mut secrets = vec![vec![F::zero(); N]; B];
    let mut first_msgs = vec![vec![G1Affine::zero(); N]; B];

    // initialize n msgs fro each party
    for i in 0..B {
        for j in 0..N {
            secrets[i][j] = F::rand(&mut rng);
        }
    }

    // initialize n msgs fro each party
    for i in 0..B {
        for j in 0..N {
            first_msgs[i][j] = g.mul(secrets[i][j]).into();
        }
    }

    // each party sends it's first round msgs
    for i in 0..B {
        a.register_msgs(&first_msgs[i], i).unwrap();
    }

    // we get output for each party per round
    // where each row is of len B (output of av for each party)
    let fr_result = a.output_first_round();

    let mut second_msgs = vec![vec![G1Affine::zero(); N]; B];
    for i in 0..B {
        for j in 0..N {
            second_msgs[i][j] = fr_result[j][i].mul(secrets[i][j]).into();
        }
    }

    // each party sends it's second round msgs
    for i in 0..B {
        a.register_msgs(&second_msgs[i], i).unwrap();
    }

    a
}

fn bench_second_round<const N: usize, const B: usize>(
    a: Auctioneer<N, B, G1Projective>,
) -> Vec<G1Affine> {
    let mut a_clone = a.clone();
    a_clone.output_second_round()
}

fn bench_first_round<const N: usize, const B: usize>(
    a: Auctioneer<N, B, G1Projective>,
) -> Vec<Vec<G1Affine>> {
    let mut a_clone = a.clone();
    a_clone.output_first_round()
}

fn round_1(c: &mut Criterion) {
    const N: usize = 8192;
    const B: usize = 256;

    let a = setup_round_1::<N, B>();
    let id = format!("Round1: range = {}, bidders = {}", N, B);
    c.bench_function(&id, |b| b.iter(|| bench_first_round(a.clone())));
}

fn round_2<const M: usize, const N: usize>(c: &mut Criterion) {
    let a = setup_round_2::<N, M>();
    let id = format!("Round2: range = {}, bidders = {}", N, M);
    c.bench_function(&id, |b| b.iter(|| bench_second_round(a.clone())));
}

fn criterion_benchmark(c: &mut Criterion) {
     // bidders
    let m: usize = env::var("M")
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(32); // default value
    
    // range
    let n: usize = env::var("N")
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(128); // default value

    match (m, n) {
        (32, 128) => round_2::<32, 128>(c),
        (32, 1024) => round_2::<32, 1024>(c),
        (32, 8192) => round_2::<32, 8192>(c),
        (128, 128) => round_2::<128, 128>(c),
        (128, 1024) => round_2::<128, 1024>(c),
        (128, 8192) => round_2::<128, 8192>(c),
        (256, 128) => round_2::<256, 128>(c),
        (256, 1024) => round_2::<256, 1024>(c),
        (256, 8192) => round_2::<256, 8192>(c),
        _ => panic!("Unsupported parameter combination (M, N): ({}, {})", m, n),
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
