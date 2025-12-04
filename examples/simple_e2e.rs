//! Simple end-to-end example for crypto-bazaar

use ark_ec::{AffineRepr, Group};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use cipher_bazaar::{auctioneer::Auctioneer, bidder::Bidder, kzg::PK, utils::srs::unsafe_setup_from_tau};
use ark_bn254::{Bn254, Fr as F, G1Affine, G1Projective};
use rand_chacha::ChaCha20Rng;
use rand::random;
use std::ops::Mul;
use ark_std::UniformRand;

fn main() {
    // prepare kzg parameters: 
    let n = 128; 
    let tau = F::from(100);
    let srs = unsafe_setup_from_tau::<G1Projective>(n - 1, tau);
    // let x_g2 = G2Projective::generator().mul(tau);
    let pk = PK::<Bn254> { srs: srs.clone() };

    let gen = G1Projective::generator();
    let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();
    let lb_at_tau = domain.evaluate_all_lagrange_coefficients(tau);

    let lagrange_basis: Vec<G1Affine> = lb_at_tau.iter().map(|li| gen.mul(li).into()).collect();
    let mut rng = ark_std::test_rng();
    let h_base = gen.mul(F::rand(&mut rng));

    const P: usize = 25; 
    const N: usize = 32;

    const B: usize = 8; // number of bidders

    // initialize auctioneer
    let mut a = Auctioneer::<N, B, G1Projective>::new();

    // initialize bidders
    let mut bidders: Vec<_> = (0..B).map(|_| Bidder::<P, N, Bn254>::new(pk.clone())).collect();
    let bids = (0..B).map(|i| i + 1).collect::<Vec<usize>>();

    // each bidder encodes its bid
    for (i, b) in bidders.iter_mut().enumerate() {
        // each bidder encodes its bi
        let seed: [u8; 32] = random();
        b.encode::<ChaCha20Rng>(bids[i], seed);
    }

    // so essentially each bidder constructs its bid well-formation proof
    // we just do it for the first bidder for demonstration
    let seed: [u8; 32] = random();
    let _proof = bidders[0].construct_bid_well_formation_proof::<ChaCha20Rng>(seed);
    
    // each bidder sends first round messages to the auctioneer
    for (i, b) in bidders.iter_mut().enumerate() {
        let first_msg = b.first_round();
        // auctioneer registers 
        a.register_msgs(&first_msg, i).unwrap();
    }
    
    // auctioneer outputs first round results
    let first_round_result = a.output_first_round();
    
    // each bidder sends second round messages to the auctioneer
    for (i, b) in bidders.iter_mut().enumerate() {
        let av_i: Vec<G1Projective> = first_round_result.iter().map(|row| row[i].into()).collect();

        let second_msg = b.second_round(&av_i);
        // auctioneer registers 
        a.register_msgs(&second_msg, i).unwrap();   
    }

    // so essentially each bidder constructs a proof of honest execution
    // we just do it for the first bidder for demonstration
    bidders[0].prove_honest_execution(&lagrange_basis, h_base);

    let result = a.output_second_round();
    let mut max_bid = 0; 
    for (i, pt) in result.iter().enumerate() {
        println!("Point: {:?}", pt);
        if pt.is_zero() {
            max_bid = i;
            break;
        }
    }
    println!("Winning bidder index: {}", max_bid);
}
