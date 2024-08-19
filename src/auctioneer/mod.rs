use self::{
    av_oracle::AVOracle,
    enums::{AVError, OracleState},
};
use ark_ec::CurveGroup;
use ark_std::cfg_iter_mut;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

mod av_oracle;
// mod av_oracle_dynamic;
pub(crate) mod enums;

#[derive(Clone)]
pub struct Auctioneer<const N: usize, const B: usize, C: CurveGroup> {
    state: OracleState,
    first_msgs_registered: usize,
    second_msgs_registered: usize,
    av_oracles: Vec<AVOracle<B, C>>,
}

impl<const N: usize, const B: usize, C: CurveGroup> Auctioneer<N, B, C> {
    pub fn new() -> Self {
        Self {
            state: OracleState::Round1Ongoing,
            first_msgs_registered: 0,
            second_msgs_registered: 0,
            av_oracles: vec![AVOracle::new(); N],
        }
    }

    pub fn register_msgs(&mut self, msgs: &Vec<C::Affine>, pos: usize) -> Result<(), AVError> {
        assert_eq!(msgs.len(), N);
        match self.state {
            OracleState::Round1Ongoing => {
                for i in 0..N {
                    self.av_oracles[i].register_msg(msgs[i], pos)?;
                }

                self.first_msgs_registered += 1;
                if self.first_msgs_registered == B {
                    self.state = OracleState::Round1Completed;
                }
            }
            OracleState::Round1Completed => {
                println!("in here");
                return Err(AVError::WrongState(String::from(
                    "Auctioneer: Message can't be sent in Round1Completed state",
                )));
            }
            OracleState::Round2Ongoing => {
                for i in 0..N {
                    self.av_oracles[i].register_msg(msgs[i], pos)?;
                }

                self.second_msgs_registered += 1;
                if self.second_msgs_registered == B {
                    self.state = OracleState::Round2Completed;
                }
            }
            OracleState::Round2Completed => {
                return Err(AVError::WrongState(String::from(
                    "Auctioneer: Message can't be sent in Round2Completed state",
                )))
            }
            OracleState::Completed => {
                return Err(AVError::WrongState(String::from(
                    "Auctioneer: Message can't be sent in Completed state",
                )))
            }
        }

        Ok(())
    }

    pub fn output_first_round(&mut self) -> Vec<Vec<C::Affine>> {
        assert_eq!(self.state, OracleState::Round1Completed);
        self.state = OracleState::Round2Ongoing;
        cfg_iter_mut!(self.av_oracles)
            .map(|av_i| av_i.output_first_round())
            .collect()
    }

    pub fn output_second_round(&mut self) -> Vec<C::Affine> {
        assert_eq!(self.state, OracleState::Round2Completed);
        self.state = OracleState::Completed;
        cfg_iter_mut!(self.av_oracles)
            .map(|av_i| av_i.output_second_round())
            .collect()
    }
}

#[cfg(test)]
mod auctioneer_tests {
    use ark_bn254::{Fr as F, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, Group};
    use ark_ff::Zero;
    use ark_std::{test_rng, UniformRand};
    use std::ops::Mul;

    use super::Auctioneer;

    const N: usize = 128;
    const B: usize = 32;

    #[test]
    fn test_many_vetos() {
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

        let av_results = a.output_second_round();
        // since each party used same secret, expect that all outputs are 0
        for i in 0..N {
            assert_eq!(av_results[i], G1Affine::zero());
        }
    }
}
