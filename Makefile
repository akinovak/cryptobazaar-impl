proofxi:
	N=128 cargo bench --bench veceq -- --sample-size 25 --measurement-time 60
	N=1024 cargo bench --bench veceq -- --sample-size 25 --measurement-time 60
	N=8192 cargo bench --bench veceq -- --sample-size 25 --measurement-time 60

proofri:
	N=128 cargo bench --bench nonzero -- --sample-size 25 --measurement-time 60
	N=1024 cargo bench --bench nonzero -- --sample-size 25 --measurement-time 60
	N=8192 cargo bench --bench nonzero -- --sample-size 25 --measurement-time 60

proofbi:
	N=128 cargo bench --bench lderivative -- --sample-size 25 --measurement-time 60
	N=1024 cargo bench --bench lderivative -- --sample-size 25 --measurement-time 60
	N=8192 cargo bench --bench lderivative -- --sample-size 25 --measurement-time 60

proofzi:
	N=128 cargo bench --bench ipa -- --sample-size 25 --measurement-time 60
	N=1024 cargo bench --bench ipa -- --sample-size 25 --measurement-time 60
	N=8192 cargo bench --bench ipa -- --sample-size 25 --measurement-time 60

avmatrix:
	M=32 N=128 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
	M=32 N=1024 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
	M=32 N=8192 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
	M=128 N=128 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
	M=128 N=1024 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
	M=128 N=8192 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 75
	M=256 N=128 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
	M=256 N=1024 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 60
	M=256 N=8192 cargo bench --bench auctioneer_r1 -- --sample-size 25 --measurement-time 75

results:
	M=32 N=128 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
	M=32 N=1024 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
	M=32 N=8192 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
	M=128 N=128 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
	M=128 N=1024 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
	M=128 N=8192 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 75
	M=256 N=128 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
	M=256 N=1024 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 60
	M=256 N=8192 cargo bench --bench auctioneer_r2 -- --sample-size 25 --measurement-time 75
