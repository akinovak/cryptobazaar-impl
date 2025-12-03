# Cryptobazaar: Private Sealed-bid Auctions at Scale

This repository provides a Rust implementation of the Cryptobazaar auction protocol and, in particular, includes the code for all of the validity proofs, the AV protocol, and the results vector computation.

## Rust

To setup Rust, please follow the [official installation instructions](https://www.rust-lang.org/tools/install). 

Minimum required Rust version: `1.80.1`.

## Tests

To run the Cryptobazaar tests, execute `cargo test` in the root folder.

## Benchmarks

There are six different microbenchmarks in total, namely for the computation of the four validity proofs, the AV protocol, and the results vector. 

To replicate the microbenchmarks provided in Table 1 of the paper, execute `./run-benchmarks.sh` in the root folder.

Alternatively, you can run the benchmarks via `Docker` by executing `docker build .` in the root folder.

**Note:** The runtime of the benchmarks depends on the used hardware. For example, on an Apple MacBook Pro M2 Max, they take about `1h` to finish.

## Attribution

If you find this code useful in your research, please cite:

[`Cryptobazaar: Private Sealed-bid Auctions at Scale - Andrija Novakovic, Alireza Kavousi, Kobi Gurkan, Philipp Jovanovic`](https://eprint.iacr.org/2024/1410)

## License

Copyright 2023-2025 Andrija Novakovic, Alireza Kavousi, Kobi Gurkan, Philipp Jovanovic. This repository is free software made available under the MIT License. For details, see the [LICENSE](LICENSE) file.

