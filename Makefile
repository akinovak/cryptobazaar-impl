
table1a:
	N=128 cargo bench --bench veceq
	N=1024 cargo bench --bench veceq
	N=8192 cargo bench --bench veceq
	N=128 cargo bench --bench nonzero
	N=1024 cargo bench --bench nonzero
	N=8192 cargo bench --bench nonzero
	N=128 cargo bench --bench lderivative
	N=1024 cargo bench --bench lderivative
	N=8192 cargo bench --bench lderivative
	N=128 cargo bench --bench ipa
	N=1024 cargo bench --bench ipa
	N=8192 cargo bench --bench ipa

table1b:
	M=32 N=128 cargo bench --bench auctioneer_r1
	M=32 N=1024 cargo bench --bench auctioneer_r1
	M=32 N=8192 cargo bench --bench auctioneer_r1
	M=128 N=128 cargo bench --bench auctioneer_r1
	M=128 N=1024 cargo bench --bench auctioneer_r1
	M=128 N=8192 cargo bench --bench auctioneer_r1
	M=256 N=128 cargo bench --bench auctioneer_r1
	M=256 N=1024 cargo bench --bench auctioneer_r1
	M=256 N=8192 cargo bench --bench auctioneer_r1

table1c:
	M=32 N=128 cargo bench --bench auctioneer_r2
	M=32 N=1024 cargo bench --bench auctioneer_r2
	M=32 N=8192 cargo bench --bench auctioneer_r2
	M=128 N=128 cargo bench --bench auctioneer_r2
	M=128 N=1024 cargo bench --bench auctioneer_r2
	M=128 N=8192 cargo bench --bench auctioneer_r2
	M=256 N=128 cargo bench --bench auctioneer_r2
	M=256 N=1024 cargo bench --bench auctioneer_r2
	M=256 N=8192 cargo bench --bench auctioneer_r2