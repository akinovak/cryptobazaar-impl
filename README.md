# Cryptobazaar: Private Sealed-bid Auctions at Scale

This repository provides a Rust implementation of the Cryptobazaar auction protocol and, in particular, includes the code for all of the validity proofs, the AV protocol, and the results vector computation.

To replicate the microbenchmarks provided in Table 1 of the paper, follow the instructions below.

## Rust

To setup Rust, please follow the [official installation instructions](https://www.rust-lang.org/tools/install).

## Benchmarks

There are six different microbenchmarks in total, namely for the computation of the four validity proofs, the AV protocol, and the results vector. 
To reproduce the benchmarks presented in Table 1, simply execute:

```
make table1a
make table1b
make table1c
```

For more fine-grained benchmarking, consider the following instructions.

- **Benchmark 1: Validity proof $\pi_{x_i}$ (Table 1a)**
    ```
    N=128 cargo bench --bench veceq
    N=1024 cargo bench --bench veceq
    N=8192 cargo bench --bench veceq
    ```

- **Benchmark 2: Validity proof $\pi_{r_i}$ (Table 1a)**
    ```
    N=128 cargo bench --bench nonzero
    N=1024 cargo bench --bench nonzero
    N=8192 cargo bench --bench nonzero
    ```

- **Benchmark 3: Validity proof $\pi_{b_i}$ (Table 1a)**
    ```
    N=128 cargo bench --bench lderivative
    N=1024 cargo bench --bench lderivative
    N=8192 cargo bench --bench lderivative
    ```

- **Benchmark 4: Validity proof $\pi_{Z_i}$ (Table 1a)**
    ```
    N=128 cargo bench --bench ipa
    N=1024 cargo bench --bench ipa
    N=8192 cargo bench --bench ipa
    ```

- **Benchmark 5: AV matrix $Y$ (Table 1b)**
    ```
    M=32 N=128 cargo bench --bench auctioneer_r1
    M=32 N=1024 cargo bench --bench auctioneer_r1
    M=32 N=8192 cargo bench --bench auctioneer_r1
    M=128 N=128 cargo bench --bench auctioneer_r1
    M=128 N=1024 cargo bench --bench auctioneer_r1
    M=128 N=8192 cargo bench --bench auctioneer_r1
    M=256 N=128 cargo bench --bench auctioneer_r1
    M=256 N=1024 cargo bench --bench auctioneer_r1
    M=256 N=8192 cargo bench --bench auctioneer_r1
    ```

- **Benchmark 6: Results vector $R$ (Table 1c)**
    ```
    M=32 N=128 cargo bench --bench auctioneer_r2
    M=32 N=1024 cargo bench --bench auctioneer_r2
    M=32 N=8192 cargo bench --bench auctioneer_r2
    M=128 N=128 cargo bench --bench auctioneer_r2
    M=128 N=1024 cargo bench --bench auctioneer_r2
    M=128 N=8192 cargo bench --bench auctioneer_r2
    M=256 N=128 cargo bench --bench auctioneer_r2
    M=256 N=1024 cargo bench --bench auctioneer_r2
    M=256 N=8192 cargo bench --bench auctioneer_r2
    ```
    







