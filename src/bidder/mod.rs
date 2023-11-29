use ark_ec::pairing::Pairing;
use rand::{RngCore, SeedableRng};

use crate::{
    bid_encoder::BidEncoder,
    gates::{structs::{Proof as GatesProof, Witness as GatesWitness, ProverIndex as GProverIndex, VerifierIndex as GVerifierIndex}, GatesArgument},
    kzg::PK as KzgPk,
};

pub struct Bidder<const P: usize, const N: usize, E: Pairing> {
    pk: KzgPk<E>,
    gp_index: GProverIndex<E::ScalarField>, 
    gv_index: GVerifierIndex<E::G1>, 
    bid_encoder: Option<BidEncoder<P, N, E::G1>>
}

impl<const P: usize, const N: usize, E: Pairing> Bidder<P, N, E> {
    pub fn new(pk: KzgPk<E>) -> Self {
        let gp_index = GatesArgument::<N, P, E>::prover_index();
        let gv_index = GatesArgument::<N, P, E>::verifier_index(&pk);
        Self {
            pk, 
            gp_index, 
            gv_index,
            bid_encoder: None, 
        }
    }
    pub fn encode<R: RngCore + SeedableRng>(&mut self, bid: usize, seed: R::Seed) {
        self.bid_encoder = Some(BidEncoder::encode::<R>(bid, seed));
    }

    pub fn construct_bid_well_formation_proof<R: RngCore + SeedableRng>(&self, seed: R::Seed) -> GatesProof<E::G1> {
        let bid_encoder = self.bid_encoder.as_ref().unwrap();
        let witness: GatesWitness<E::ScalarField> = bid_encoder.to_gate_witness::<R>(seed);
        GatesArgument::<N, P, E>::prove(&witness, &self.gv_index, &self.gp_index, &self.pk)
    }

    pub fn first_round(&self) -> Vec<E::G1Affine> {
        let bid_encoder = self.bid_encoder.as_ref().unwrap();
        bid_encoder.to_first_av_round()
    }

    pub fn second_round(&self, basis: &[E::G1]) -> Vec<E::G1Affine> {
        let bid_encoder = self.bid_encoder.as_ref().unwrap();
        bid_encoder.to_second_av_round(&basis)
    }

    // TODO: IPA proofs
    pub fn prove_honest_execution() {

    }
}
