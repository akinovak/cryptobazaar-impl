//! Simple end-to-end example for crypto-bazaar

use ark_ec::{AffineRepr, Group};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use cipher_bazaar::{auctioneer::Auctioneer, bidder::Bidder, kzg::PK, utils::srs::unsafe_setup_from_tau};
use ark_bn254::{Bn254, Fr as F, G1Affine, G1Projective};
use rand_chacha::ChaCha20Rng;
use rand::random;
use rand::Rng;
use std::ops::Mul;
use ark_std::UniformRand;

fn main() {
    // Prepare KZG parameters
    let n = 128; 
    let tau = F::from(100);
    let srs = unsafe_setup_from_tau::<G1Projective>(n - 1, tau);
    let pk = PK::<Bn254> { srs: srs.clone() };

    // Prepare IPA proof parameters
    let gen = G1Projective::generator();
    let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();
    let lb_at_tau = domain.evaluate_all_lagrange_coefficients(tau);

    let lagrange_basis: Vec<G1Affine> = lb_at_tau.iter().map(|li| gen.mul(li).into()).collect();
    let mut rng = ark_std::test_rng();
    let h_base = gen.mul(F::rand(&mut rng));

    // Prepare auction parameters
    const P: usize = 25; // bid range
    const N: usize = 32; // next power of 2 (greater than P) for IPP etc.
    const B: usize = 8; // number of bidders

    // Initialize the auctioneer and the bidders
    let mut auctioneer = Auctioneer::<N, B, G1Projective>::new();
    let mut bidders: Vec<_> = (0..B).map(|_| Bidder::<P, N, Bn254>::new(pk.clone())).collect();
    let mut rng = rand::thread_rng();
    let bids = (0..B)
        .map(|_| rng.gen_range(1..=P))
        .collect::<Vec<usize>>();    

    // Each bidder encodes its bid, computes a bid correctness proof and sends its first message to the auctioneer who registers each message
    for i in 0..bidders.len() {
        let seed: [u8; 32] = random();
        bidders[i].encode::<ChaCha20Rng>(bids[i], seed);        
        let first_msg = bidders[i].first_round();
        let _proof = bidders[i].construct_bid_well_formation_proof::<ChaCha20Rng>(seed);
        auctioneer.register_msgs(&first_msg, i).unwrap();
    }
    
    // The auctioneer computes and outputs the first round AV results
    let first_round_result = auctioneer.output_first_round();
    
    // Each bidder computes their second round message based on the AV results together with a correctness proof and sends it to the auctioneer who again registers each message
    for i in 0..bidders.len() {
        let av_i: Vec<G1Projective> = first_round_result.iter().map(|row| row[i].into()).collect();
        let second_msg = bidders[i].second_round(&av_i);
        let _proof = bidders[i].prove_honest_execution(&lagrange_basis, h_base);
        auctioneer.register_msgs(&second_msg, i).unwrap();   
    }

    // The auctioneer computes and outputs the second round AV results 
    let result = auctioneer.output_second_round();

    // To determine the winner check for the zero point
    let mut max_bid = 0; 
    for (i, pt) in result.iter().enumerate() {
        println!("Point: {:?}", pt);
        if pt.is_zero() {
            max_bid = i;
            break;
        }
    }
    println!("Bids: {:?}", bids);
    println!("Winning bid: {}", max_bid);
}
