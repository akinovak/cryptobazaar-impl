# Docker environment to build Cryptobazaar and run microbenchmarks.
# A file with the output can be found in /cryptobazaar/benchmark-results.txt.
# Sources are copied into /cryptobazaar.

FROM rust:1.91.1-trixie

# Get the sources....
RUN mkdir /cryptobazaar
WORKDIR /cryptobazaar
RUN git clone https://github.com/akinovak/cryptobazaar-impl.git .

# Build...
ENV RUSTFLAGS="-C target-cpu=native"
RUN cargo build --release

# Run benchmarks...
RUN ./run-benchmarks.sh 2>&1 | tee benchmark-results.txt
