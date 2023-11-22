use ark_std::One;
use std::ops::Mul;

pub fn compute_folding_coeffs<T>(chs: &[T]) -> Vec<T>
where
    T: Sized + Copy + One + Mul,
{
    let l = chs.len();

    let mut c: Vec<Vec<T>> = Vec::with_capacity(l);
    for i in 0..l {
        c.push(vec![T::one(); 1 << (i + 1)])
    }

    // first array is equal to [1][ch_0]
    c[0][1] = chs[0];

    for i in 0..(l - 1) {
        for j in 0..(1 << (i + 1)) {
            c[i + 1][2 * j] = c[i][j];
            c[i + 1][2 * j + 1] = chs[i + 1] * c[i][j];
        }
    }

    c[l - 1].clone()
}