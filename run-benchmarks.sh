#!/bin/bash

echo "----------------------------------------------------------"
echo "Running benchmarks for proof \\pi_{x_i}"
echo "----------------------------------------------------------"

N=128 cargo bench --bench veceq -- --sample-size 25 --measurement-time 60
N=1024 cargo bench --bench veceq -- --sample-size 25 --measurement-time 60
N=8192 cargo bench --bench veceq -- --sample-size 25 --measurement-time 60

echo "----------------------------------------------------------"
echo "Running benchmarks for proof \\pi_{r_i}"
echo "----------------------------------------------------------"

N=128 cargo bench --bench nonzero -- --sample-size 25 --measurement-time 60
N=1024 cargo bench --bench nonzero -- --sample-size 25 --measurement-time 60
N=8192 cargo bench --bench nonzero -- --sample-size 25 --measurement-time 60

echo "----------------------------------------------------------"
echo "Running benchmarks for proof \\pi_{b_i}"
echo "----------------------------------------------------------"

N=128 cargo bench --bench lderivative -- --sample-size 25 --measurement-time 60
N=1024 cargo bench --bench lderivative -- --sample-size 25 --measurement-time 60
N=8192 cargo bench --bench lderivative -- --sample-size 25 --measurement-time 60

echo "----------------------------------------------------------"
echo "Running benchmarks for proof \\pi_{Z_i}"
echo "----------------------------------------------------------"

N=128 cargo bench --bench ipa -- --sample-size 25 --measurement-time 60
N=1024 cargo bench --bench ipa -- --sample-size 25 --measurement-time 60
N=8192 cargo bench --bench ipa -- --sample-size 25 --measurement-time 60

echo "----------------------------------------------------------"
echo "Running benchmarks for AV protocol"
echo "----------------------------------------------------------"

M=32 N=128 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
M=32 N=1024 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
M=32 N=8192 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
M=128 N=128 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
M=128 N=1024 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
M=128 N=8192 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 90
M=256 N=128 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
M=256 N=1024 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
M=256 N=8192 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 130

echo "----------------------------------------------------------"
echo "Running benchmarks for results vector"
echo "----------------------------------------------------------"

M=32 N=128 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
M=32 N=1024 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
M=32 N=8192 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
M=128 N=128 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
M=128 N=1024 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
M=128 N=8192 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 90
M=256 N=128 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
M=256 N=1024 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
M=256 N=8192 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 90
