use ark_ff::FftField;

pub mod folding;
pub mod srs;

pub fn is_pow_2(x: usize) -> bool {
    (x & (x - 1)) == 0
}

pub fn powers_of_x<F: FftField>(x: F, n: usize) -> Vec<F> {
    std::iter::successors(Some(F::one()), |p| Some(*p * x))
        .take(n)
        .collect()

}