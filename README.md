# cryptobazaar-impl

This library implements all necessary arguments of cryptobazaar: auctioneer, bid encoder, inner product argument, log derivative part, univariate sumcheck, pedersen schnorr equality and univariate sumcheck pedersen commitment equality. It includes several benchmarks to help measure the performance of the protocol. You can run the benchmarks using the instructions below.

## Benchmarks

We have defined six benchmarks to evaluate key areas of the library that should match numbers displayed in `Table 1` of the paper:

1. **Benchmark 1: `veceq`**
    - Measures the speed of proving that KZG committed vector is equal to vector committed behind array of elliptic curve points 
    - Matches $\pi_{x_i}$ of the `Table 1` part `(a)`
    - Run with ``cargo bench --bench veceq``

2. **Benchmark 2: `nonzero`**
    - Measures the speed of proving that committed vector has non zero entires
    - Matches $\pi_{r_i}$ of the `Table 1` part `(a)`
    - Run with ``cargo bench --bench nonzero``

3. **Benchmark 3: `lderivative`**
    - Measures the speed of log derivative argument for proving that bid is a valid unary encoded vector
    - Matches $\pi_{b_i}$ of the `Table 1` part `(a)`
    - Run with ``cargo bench --bench lderivative``

4. **Benchmark 4: `ipa`**
    - Measures the performance of computing the bidder's second round output 
    - Matches $\pi_{Z_i}$ of the `Table 1` part `(a)`
    - Run with ``cargo bench --bench ipa``

5. **Benchmark 5: `auctioneer_r1`**
    - Measures the performance of the auctioneer to compute AV matrix Y given number of bidders and price range
    - Matches `Table 1` part `(b)` 
    - Run with ``cargo bench --bench auctioneer``

6. **Benchmark 6: `auctioneer_r2`**
    - Measures the performance of the auctioneer to compute results vector R
    - Matches `Table 1` part `(c)` 
    - Run with ``cargo bench --bench auctioneer``







