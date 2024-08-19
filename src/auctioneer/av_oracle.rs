// Oracle that computes outputs of the rounds of AV

use super::enums::{AVError, OracleState};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, Zero};

// TODO: handle errors instead of panics
#[derive(Clone)]
pub struct AVOracle<const B: usize, C: CurveGroup> {
    state: OracleState,
    first_msgs: Vec<C::Affine>,
    first_msgs_registered: usize,
    second_msgs: Vec<C::Affine>,
    second_msgs_registered: usize,
}

impl<const B: usize, C: CurveGroup> AVOracle<B, C> {
    pub fn new() -> Self {
        Self {
            state: OracleState::Round1Ongoing,
            first_msgs: vec![C::Affine::zero(); B],
            first_msgs_registered: 0,
            second_msgs: vec![C::Affine::zero(); B],
            second_msgs_registered: 0,
        }
    }

    fn msg_validity(&self, msg: C::Affine, pos: usize) -> Result<(), AVError> {
        let zero = C::Affine::zero();
        if pos >= B {
            return Err(AVError::WrongPosition(format!(
                "AV: Position has to be less than {}",
                B
            )));
        }
        if msg == zero {
            return Err(AVError::WrongMsg(String::from("AV: Message can't be zero")));
        }
        // assert that position is not already used
        match self.state {
            OracleState::Round1Ongoing => {
                if self.first_msgs[pos] != zero {
                    return Err(AVError::MsgAlreadySent(pos));
                }
            }
            OracleState::Round2Ongoing => {
                if self.second_msgs[pos] != zero {
                    return Err(AVError::MsgAlreadySent(pos));
                }
            }
            OracleState::Round1Completed => {
                return Err(AVError::WrongState(String::from(
                    "AV: Message can't be sent in Round1Completed state",
                )))
            }
            OracleState::Round2Completed => {
                return Err(AVError::WrongState(String::from(
                    "AV: Message can't be sent in Round2Completed state",
                )))
            }
            OracleState::Completed => {
                return Err(AVError::WrongState(String::from(
                    "AV: Message can't be sent in Completed state",
                )))
            }
        }

        Ok(())
    }

    pub fn register_msg(&mut self, msg: C::Affine, pos: usize) -> Result<(), AVError> {
        self.msg_validity(msg, pos)?;
        match self.state {
            OracleState::Round1Ongoing => {
                self.first_msgs[pos] = msg;
                self.first_msgs_registered += 1;

                if self.first_msgs_registered == B {
                    self.state = OracleState::Round1Completed;
                }
            }
            OracleState::Round2Ongoing => {
                self.second_msgs[pos] = msg;
                self.second_msgs_registered += 1;

                if self.second_msgs_registered == B {
                    self.state = OracleState::Round2Completed;
                }
            }
            _ => panic!("AV: Something went wrong in register_msg"),
        }

        Ok(())
    }

    pub fn output_first_round(&mut self) -> Vec<C::Affine> {
        assert_eq!(self.state, OracleState::Round1Completed);

        // compute msgs
        // let mut x = [-C::ScalarField::one(); B];
        // x[0] = C::ScalarField::zero();

        let mut x = [C::ScalarField::one(); B];
        x[B - 1] = C::ScalarField::zero();

        let mut outputs = vec![C::zero(); B];
        outputs[B - 1] = C::msm(&self.first_msgs, &x).unwrap();

        /*
           0 -1 -1 -1
           1  0 -1 -1
           1  1  0 -1
           1  1  1  0
        */
        for i in 0..(B - 1) {
            let idx = B - 2 - i;
            outputs[idx] = outputs[idx + 1] - self.first_msgs[idx + 1] - self.first_msgs[idx];
        }

        self.state = OracleState::Round2Ongoing;

        C::normalize_batch(&outputs)
    }

    pub fn output_second_round(&mut self) -> C::Affine {
        assert_eq!(self.state, OracleState::Round2Completed);
        self.state = OracleState::Completed;

        let ones = vec![C::ScalarField::one(); B];
        C::msm(&self.second_msgs, &ones).unwrap().into()
    }
}

#[cfg(test)]
mod av_oracle_tests {
    use ark_bn254::{Fr as F, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, Group};
    use ark_std::{test_rng, UniformRand};
    use std::ops::Mul;

    use super::AVOracle;
    const B: usize = 1024;
    use rayon::prelude::*;

    #[test]
    fn rayon() {
        println!("Number of CPU cores utilized: {}", rayon::current_num_threads());
    }

    #[test]
    fn no_veto() {
        let mut rng = test_rng();
        let g = G1Projective::generator();

        let mut av_oracle = AVOracle::<B, G1Projective>::new();

        let party_secrets: Vec<_> = (0..B).map(|_| F::rand(&mut rng)).collect();
        let first_msgs: Vec<G1Affine> = party_secrets.iter().map(|mi| g.mul(mi).into()).collect();

        for i in 0..B {
            av_oracle.register_msg(first_msgs[i], i).unwrap();
        }

        let round_outputs = av_oracle.output_first_round();
        let second_msgs: Vec<G1Affine> = party_secrets
            .iter()
            .zip(round_outputs.iter())
            .map(|(mi, &ri)| ri.mul(mi).into())
            .collect();

        for i in 0..B {
            av_oracle.register_msg(second_msgs[i], i).unwrap();
        }

        let output = av_oracle.output_second_round();
        assert_eq!(output, G1Affine::zero());
    }

    #[test]
    fn veto() {
        let mut rng = test_rng();
        let g = G1Projective::generator();

        let mut av_oracle = AVOracle::<B, G1Projective>::new();

        let mut party_secrets: Vec<_> = (0..B).map(|_| F::rand(&mut rng)).collect();
        let first_msgs: Vec<G1Affine> = party_secrets.iter().map(|mi| g.mul(mi).into()).collect();

        for i in 0..B {
            av_oracle.register_msg(first_msgs[i], i).unwrap();
        }

        let round_outputs = av_oracle.output_first_round();

        // at least one party picks a new secret
        party_secrets[0] = F::rand(&mut rng);

        let second_msgs: Vec<G1Affine> = party_secrets
            .iter()
            .zip(round_outputs.iter())
            .map(|(mi, &ri)| ri.mul(mi).into())
            .collect();

        for i in 0..B {
            av_oracle.register_msg(second_msgs[i], i).unwrap();
        }

        let output = av_oracle.output_second_round();
        assert_ne!(output, G1Affine::zero());
    }
}
