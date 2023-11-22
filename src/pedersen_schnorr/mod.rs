use std::{marker::PhantomData, ops::Mul};

use ark_ec::CurveGroup;
use ark_std::{rand::RngCore, UniformRand};

use crate::pedersen_schnorr::tr::Transcript;

use self::structs::{Error, Instance, Proof, Witness};

pub mod structs;
mod tr;

/*
    Given points Q, P and H prove knowledge of opening of pedersen commitments
    1. X_1 = aQ + r_1H
    2. X_2 = aP + r_2H

    Round1:
    p.1.1. samples (b_1, b_2, b_3)
    p.1.2. sends R_1 = b_1Q + b_2H
    p.1.3. sends R_2 = b_1P + b_3H

    v.1.1 Sends random c

    Round2:
    p.2.1. sends z_1 = ca + b_1
    p.2.1. sends z_2 = cr_1 + b_2
    p.2.1. sends z_3 = cr_2 + b_3

    v.2.1 cX_1 + R_1 = z_1Q + z_2H
    v.2.2 cX_2 + R_2 = z_1P + z_3H
*/

pub struct Argument<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup> Argument<C> {
    pub fn prove<R: RngCore>(
        instance: &Instance<C>,
        witness: &Witness<C::ScalarField>,
        rng: &mut R,
    ) -> Proof<C> {
        let mut tr = Transcript::<C>::new(b"pedersen-schnorr");
        tr.send_instance(instance);

        let (b_1, b_2, b_3) = (
            C::ScalarField::rand(rng),
            C::ScalarField::rand(rng),
            C::ScalarField::rand(rng),
        );

        let rand_1 = (instance.q_base.mul(&b_1) + instance.h_base.mul(&b_2)).into();
        let rand_2 = (instance.p_base.mul(&b_1) + instance.h_base.mul(&b_3)).into();

        tr.send_blinders(&rand_1, &rand_2);
        let c = tr.get_c();

        let z_1 = c * witness.a + b_1;
        let z_2 = c * witness.r_1 + b_2;
        let z_3 = c * witness.r_2 + b_3;

        Proof {
            rand_1,
            rand_2,
            z_1,
            z_2,
            z_3,
        }
    }

    pub fn verify(instance: &Instance<C>, proof: &Proof<C>) -> Result<(), Error> {
        let mut tr = Transcript::<C>::new(b"pedersen-schnorr");
        tr.send_instance(instance);

        tr.send_blinders(&proof.rand_1, &proof.rand_2);
        let c = tr.get_c();

        let eq1 = {
            instance.x_1.mul(c) + proof.rand_1
                == instance.q_base.mul(proof.z_1) + instance.h_base.mul(proof.z_2)
        };

        if !eq1 {
            return Err(Error::Relation1);
        }

        let eq2 = {
            instance.x_2.mul(c) + proof.rand_2
                == instance.p_base.mul(proof.z_1) + instance.h_base.mul(proof.z_3)
        };

        if !eq2 {
            return Err(Error::Relation1);
        }

        Ok(())
    }
}

#[cfg(test)]
mod pedersen_schnorr_test {
    use std::ops::Mul;

    use ark_bn254::{Fr as F, G1Affine, G1Projective};
    use ark_ec::Group;
    use ark_std::test_rng;

    use super::{
        structs::{Instance, Witness},
        Argument,
    };
    #[test]
    fn simple_test() {
        let mut rng = test_rng();
        let g = G1Projective::generator();

        // setup bases
        let q = F::from(100u64);
        let p = F::from(200u64);
        let h = F::from(300u64);

        let q_base: G1Affine = g.mul(&q).into();
        let p_base: G1Affine = g.mul(&p).into();
        let h_base: G1Affine = g.mul(&h).into();

        // witness
        let a = F::from(3u64);
        let r_1 = F::from(7u64);
        let r_2 = F::from(13u64);

        // instance
        let x_1 = q_base.mul(&a) + h_base.mul(&r_1);
        let x_2 = p_base.mul(&a) + h_base.mul(&r_2);

        let instance = Instance::<G1Projective> {
            q_base,
            p_base,
            h_base,
            x_1: x_1.into(),
            x_2: x_2.into(),
        };

        let witness = Witness::<F> { a, r_1, r_2 };

        let proof = Argument::prove(&instance, &witness, &mut rng);
        let result = Argument::verify(&instance, &proof);
        assert!(result.is_ok());
    }
}
