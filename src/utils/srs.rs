use ark_ec::CurveGroup;
use ark_ff::One;

/// Create srs from specific tau
pub fn unsafe_setup_from_tau<C: CurveGroup>(
    max_power: usize,
    tau: C::ScalarField,
) -> Vec<C::Affine> {
    let powers_of_tau: Vec<C::ScalarField> =
        std::iter::successors(Some(C::ScalarField::one()), |p| Some(*p * tau))
            .take(max_power + 1)
            .collect();

    let gen = C::generator();
    let srs: Vec<C> = powers_of_tau.iter().map(|tp| gen.mul(tp)).collect();

    C::normalize_batch(&srs)
}
