pub mod folding;
pub mod srs;

pub fn is_pow_2(x: usize) -> bool {
    (x & (x - 1)) == 0
}
