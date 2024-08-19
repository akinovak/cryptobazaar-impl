use std::ops::Mul;

use ark_bn254::{Fr as F, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group};
use ark_ff::Zero;
use ark_std::{test_rng, UniformRand};
use cipher_bazaar::auctioneer::Auctioneer;
use criterion::{criterion_group, criterion_main, Criterion};

/* RUN WITH: cargo bench --bench auctioneer */

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

fn round_2(c: &mut Criterion) {
    const N: usize = 32;
    const B: usize = 32;

    let a = setup_round_2::<N, B>();
    let id = format!("Round2: range = {}, bidders = {}", N, B);
    c.bench_function(&id, |b| b.iter(|| bench_second_round(a.clone())));
}

fn criterion_benchmark(c: &mut Criterion) {
    // round_1(c);
    round_2(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
