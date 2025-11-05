# Cryptobazaar: Private Sealed-bid Auctions at Scale

This repository provides a Rust implementation of the Cryptobazaar auction protocol and, in particular, includes the code for all of the validity proofs, the AV protocol, and the results vector computation.

To replicate the microbenchmarks provided in Table 1 of the paper, follow the instructions below.

## Rust

To setup Rust, please follow the [official installation instructions](https://www.rust-lang.org/tools/install).

## Benchmarks

There are six different microbenchmarks in total, namely for the computation of the four validity proofs, the AV protocol, and the results vector. 

To reproduce the benchmarks presented in Table 1, consider the following instructions.

**Benchmark 1: Validity proof $\pi_{x_i}$ (Table 1a)**
```
make proofxi
```

**Benchmark 2: Validity proof $\pi_{r_i}$ (Table 1a)**
```
make proofri
```

**Benchmark 3: Validity proof $\pi_{b_i}$ (Table 1a)**
```
make proofbi
```

**Benchmark 4: Validity proof $\pi_{Z_i}$ (Table 1a)**
```
make proofzi
```

**Benchmark 5: AV matrix $Y$ (Table 1b)**
```
make avmatrix
```

**Benchmark 6: Results vector $R$ (Table 1c)**
```
make results
```
