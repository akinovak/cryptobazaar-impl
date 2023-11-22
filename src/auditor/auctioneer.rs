use ark_ec::CurveGroup;
use ark_ff::{One, Zero};

pub struct AVAuditor<const B: usize, C: CurveGroup> {
    pub(crate) first_round_msgs: [C::Affine; B],
    pub(crate) first_round_output: [C::Affine; B],
    pub(crate) second_round_msgs: [C::Affine; B],
    pub(crate) second_round_output: C::Affine,
}

// TODO: make corresponding error
impl<const B: usize, C: CurveGroup> AVAuditor<B, C> {
    pub fn audit(&self) -> bool {
        let mut x = [-C::ScalarField::one(); B];
        x[0] = C::ScalarField::zero();

        let mut outputs = vec![C::zero(); B];
        outputs[0] = C::msm(&self.first_round_msgs, &x).unwrap();

        /*
           0 -1 -1 -1
           1  0 -1 -1
           1  1  0 -1
           1  1  1  0
        */
        for i in 1..B {
            outputs[i] = outputs[i - 1] + self.first_round_msgs[i - 1] + self.first_round_msgs[i];
        }

        let first_round_res = C::normalize_batch(&outputs);

        let ones = vec![C::ScalarField::one(); B];
        let second_round_res = C::msm(&self.second_round_msgs, &ones).unwrap().into();

        return first_round_res == self.first_round_output
            && second_round_res == self.second_round_output;
    }
}

pub struct AuctioneerAuditor<const N: usize, const B: usize, C: CurveGroup> {
    av_auditor: [AVAuditor<B, C>; N],
}

// TODO: wrap in error
impl<const N: usize, const B: usize, C: CurveGroup> AuctioneerAuditor<N, B, C> {
    pub fn audit(&self) -> bool {
        for i in 0..N {
            if !self.av_auditor[i].audit() {
                return false;
            }
        }

        return true;
    }
}
