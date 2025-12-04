use ark_ec::pairing::Pairing;
use ark_ec::VariableBaseMSM;
use rand::{RngCore, SeedableRng};

use crate::{
    bid_encoder::BidEncoder, gates::{
        GatesArgument, structs::{
            Proof as GatesProof, ProverIndex as GProverIndex, VerifierIndex as GVerifierIndex,
            Witness as GatesWitness,
        }
    }, ipa::{InnerProduct, structs::Witness as IPAWitness, structs::Proof as IPAProof, structs::Instance as IPAInstance}, kzg::PK as KzgPk
};

pub struct Bidder<const P: usize, const N: usize, E: Pairing> {
    pk: KzgPk<E>,
    gp_index: GProverIndex<E::ScalarField>,
    gv_index: GVerifierIndex<E::G1>,
    bid_encoder: Option<BidEncoder<P, N, E::G1>>,
    av_response: Option<Vec<E::G1>>,
    second_round_msg: Option<Vec<E::G1Affine>>,
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
            av_response: None,
            second_round_msg: None,
        }
    }
    pub fn encode<R: RngCore + SeedableRng>(&mut self, bid: usize, seed: R::Seed) {
        self.bid_encoder = Some(BidEncoder::encode::<R>(bid, seed));
    }

    pub fn construct_bid_well_formation_proof<R: RngCore + SeedableRng>(
        &self,
        seed: R::Seed,
    ) -> GatesProof<E::G1> {
        let bid_encoder = self.bid_encoder.as_ref().unwrap();
        let witness: GatesWitness<E::ScalarField> = bid_encoder.to_gate_witness::<R>(seed);
        GatesArgument::<N, P, E>::prove(&witness, &self.gv_index, &self.gp_index, &self.pk)
    }

    pub fn first_round(&self) -> Vec<E::G1Affine> {
        let bid_encoder = self.bid_encoder.as_ref().unwrap();
        bid_encoder.to_first_av_round()
    }

    pub fn second_round(&mut self, basis: &[E::G1]) -> Vec<E::G1Affine> {
        let bid_encoder = self.bid_encoder.as_ref().unwrap();
        let msg = bid_encoder.to_second_av_round(&basis);
        self.av_response = Some(basis.to_vec());
        self.second_round_msg = Some(msg.clone());
        msg
    }

    pub fn prove_honest_execution(&self, lagrange_basis: &[E::G1Affine], h_base: E::G1) -> IPAProof<5, E::G1> {
        let wtns = self.bid_encoder.as_ref().unwrap().to_ipa_witness();
        let ipa_witness = IPAWitness { a: wtns.clone().try_into().unwrap() };

        let ac = E::G1::msm(lagrange_basis, &wtns).unwrap();
        let b: Vec<E::G1Affine> = self.av_response.clone().unwrap().iter().map(|&pt| pt.into()).collect();
        let c = self.second_round_msg.clone().unwrap();
        let instance = IPAInstance::<N, E::G1> {
            ac: ac.into(),
            b: b.try_into().unwrap(),
            h_base: h_base.into(),
            c: c.try_into().unwrap(),
        };

        let mut rng = ark_std::test_rng();
        let proof = InnerProduct::<N, 5, E>::prove::<_>(
            &instance,
            &ipa_witness,
            &self.pk,
            &mut rng,
        );
        proof
    }
}
