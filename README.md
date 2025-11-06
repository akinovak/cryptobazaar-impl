# Cryptobazaar: Private Sealed-bid Auctions at Scale

This repository provides a Rust implementation of the Cryptobazaar auction protocol and, in particular, includes the code for all of the validity proofs, the AV protocol, and the results vector computation.

## Rust

To setup Rust, please follow the [official installation instructions](https://www.rust-lang.org/tools/install).

## Benchmarks

There are six different microbenchmarks in total, namely for the computation of the four validity proofs, the AV protocol, and the results vector. 

To replicate the microbenchmarks provided in Table 1 of the paper, execute `./run-benchmarks.sh`.

