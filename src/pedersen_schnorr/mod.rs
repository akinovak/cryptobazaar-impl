use std::{marker::PhantomData, ops::Mul};

use ark_ec::CurveGroup;
use ark_std::{rand::RngCore, UniformRand};

use self::structs::{Error, Instance, Proof, Witness};
use self::tr::Transcript;

pub mod structs;
mod tr;

/*
    Given points P and H prove knowledge of opening of pedersen commitments
    X = xQ + rH

    Round1:
    p.1.1. samples (b_1, b_2)
    p.1.2. sends R = b_1P + b_2H

    v.1.1 Sends random c

    Round2:
    p.2.1. sends z_1 = cx + b_1
    p.2.1. sends z_2 = cr + b_2

    v.2.1 cX + R = z_1P + z_2H
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

        let (b_1, b_2) = (C::ScalarField::rand(rng), C::ScalarField::rand(rng));

        let blinder = (instance.p_base.mul(&b_1) + instance.h_base.mul(&b_2)).into();

        tr.send_blinder(&blinder);
        let c = tr.get_c();

        let z_1 = c * witness.x + b_1;
        let z_2 = c * witness.r + b_2;

        Proof { blinder, z_1, z_2 }
    }

    pub fn verify(instance: &Instance<C>, proof: &Proof<C>) -> Result<(), Error> {
        let mut tr = Transcript::<C>::new(b"pedersen-schnorr");
        tr.send_instance(instance);

        tr.send_blinder(&proof.blinder);
        let c = tr.get_c();

        let eq = {
            instance.x.mul(c) + proof.blinder
                == instance.p_base.mul(proof.z_1) + instance.h_base.mul(proof.z_2)
        };

        if !eq {
            return Err(Error::RelationCheckFailed);
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
        let p = F::from(200u64);
        let h = F::from(300u64);

        let p_base: G1Affine = g.mul(&p).into();
        let h_base: G1Affine = g.mul(&h).into();

        // witness
        let x_witness = F::from(3u64);
        let r = F::from(7u64);

        // instance
        let x = p_base.mul(&x_witness) + h_base.mul(&r);

        let instance = Instance::<G1Projective> {
            p_base,
            h_base,
            x: x.into(),
        };

        let witness = Witness::<F> { x: x_witness, r };

        let proof = Argument::prove(&instance, &witness, &mut rng);
        let result = Argument::verify(&instance, &proof);
        assert!(result.is_ok());
    }
}
