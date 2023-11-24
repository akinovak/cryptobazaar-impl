use std::ops::Mul;

use ark_ec::{Group, VariableBaseMSM, pairing::Pairing};
use ark_poly::{GeneralEvaluationDomain, EvaluationDomain};
use ark_std::rand::RngCore;
use ark_bn254::{Fr as F, G1Projective, Bn254, G1Affine};
use ark_std::UniformRand;
use cipher_bazaar::{utils::srs::unsafe_setup_from_tau, kzg::PK, ipa::{structs::{Instance, Witness}, DoubleInnerProduct}};
use criterion::{criterion_group, criterion_main, Criterion};


/* RUN WITH: cargo bench --bench ipa */

const N: usize = 8192;
const LOG_N: usize = 13;

fn prove<const N: usize, E: Pairing, R: RngCore>(instance: &Instance<N, E::G1>, witness: &Witness<N, E::ScalarField>, pk: &PK<E>, rng: &mut R) {
    DoubleInnerProduct::<N, LOG_N, E>::prove::<_>(instance, witness, pk, rng);
}

fn criterion_benchmark(criterion: &mut Criterion) {
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
        lagrange_basis: lagrange_basis.try_into().unwrap(),
        b: b.try_into().unwrap(),
        h_base: h_base.into(),
        c: c.try_into().unwrap(),
    };

    let witness = Witness::<N, F> {
        a: a.try_into().unwrap(),
    };

    let id = format!("proof {}", N);
    criterion.bench_function(&id, |b| b.iter(|| prove::<N, Bn254, _>(&instance, &witness, &pk, &mut rng)));

}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);