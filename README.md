# Cryptobazaar: Private Sealed-bid Auctions at Scale

This repository provides a Rust implementation of the [Cryptobazaar](https://eprint.iacr.org/2024/1410) auction protocol and includes the code for all of the validity proofs, the AV protocol, and the results vector computation.

## Rust

To setup Rust, please follow the [official installation instructions](https://www.rust-lang.org/tools/install). 

The minimum required Rust version is `1.80.1`.

## Tests

To run the Cryptobazaar tests, execute `cargo test` in the root folder.

## Example

To execute a sample Cryptobazaar auction, execute `cargo run --example simple_e2e` in the root folder. The corresponding code showing the protocol flow can be found in `examples/simple_e2e.rs`.

## Benchmarks

There are six different microbenchmarks in total, namely for the computation of the four validity proofs, the AV protocol, and the results vector. 

To replicate the microbenchmarks provided in Table 1 of the paper, execute `./run-benchmarks.sh` in the root folder.

Alternatively, you can run the benchmarks via `Docker` by executing `docker build .` in the root folder.

**Note:** Benchmark runtimes depend on your hardware and CPU architecture. For example, enabling the `asm` feature utilizes AVX instructions on Intel CPUs for faster performance. On Apple Silicon, AVX instructions are not available, so runtimes may differ. For example, on an Apple MacBook Pro M2 Max with 96 GB RAM, the benchmarks take about `1h` to finish.

## Attribution

If you find this work useful in your research, please cite it via:

```
@inproceedings{novakovic2026cryptobazaar
    author = {Andrija Novakovic and Alireza Kavousi and Kobi Gurkan and Philipp Jovanovic},
    title = {Cryptobazaar: Private Sealed-bid Auctions at Scale},
    booktitle = {33nd Annual Network and Distributed System Security Symposium, {NDSS} 2026, San Diego, California, USA, 23-27 February, 2026},
    publisher = {The Internet Society},
    year = {2026},
}
```

## License

Copyright 2023-2025 Andrija Novakovic, Alireza Kavousi, Kobi Gurkan, Philipp Jovanovic. This repository is free software made available under the MIT License. For details, see the [LICENSE](LICENSE) file.

