# cryptobazaar-impl

This library implements all necessary arguments of cryptobazaar: auctioneer, bid encoder, inner product argument, log derivative part, univariate sumcheck, pedersen schnorr equality and univariate sumcheck pedersen commitment equality. It includes several benchmarks to help measure the performance of the protocol. You can run the benchmarks using the instructions below.

## Benchmarks

We have defined six benchmarks to evaluate key areas of the library:

1. **Benchmark 1: `auctioneer`**
    - Measures the performance of the auctioneer given number of bidders and price range
    - Run with ``cargo bench --bench auctioneer``
    
2. **Benchmark 2: `encode`**
    - Measures the speed of bid encoding
    - Run with ``cargo bench --bench encode``
    
3. **Benchmark 3: `ipa`**
    - Measures the performance of inner product argument that is used in the second round of the protocol
    - Run with ``cargo bench --bench ipa``

4. **Benchmark 4: `lderivative`**
    - Measures the speed of log derivative argument for proving that bid is a valid unary encoded vector
    - Run with ``cargo bench --bench lderivative``

5. **Benchmark 5: `nonzero`**
    - Measures the speed of proving that committed vector has non zero entires
    - Run with ``cargo bench --bench nonzero``
◊
6. **Benchmark 6: `veceq`**
    - Measures the speed of proving that KZG committed vector is equal to vector committed behind array of elliptic curve points 
    - Run with ``cargo bench --bench veceq``

