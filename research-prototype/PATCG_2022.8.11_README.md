
# PATCG 8/11 Benchmarks

Here are the run commands for the benchmarks we shared of IPA the the 8/11/22 PATCG.

We ran with the 3 party honest majority malicious protocol  `sy-rep-ring-party.x` with the default statistical security of 40 bits. For semi-honest we ran replicated secret sharing protocol `ring.sh`.

To enable mod 2^k ring computation with custom k, add `MOD = -DRING_SIZE=32` to `MP-SPDZ/CONFIG.mine` and rebuild with `make -B -j8 sy-rep-ring-party.x` .  All of our results are were for k = 32.

All of the MPC code is in the `research_prototype/ipa/` directory, and can be accessed by running `python ipa` within this directory (`research_prototype/`.) This provides a CLI for both compiling and generating input.

You'll need to fill in the `<p0.hostname>` value in the commands.


The particular commit we benchmarked was [https://github.com/bmcase/raw-ipa/commit/8432970926cecef90da3e2bf6202577950d887d6](https://github.com/bmcase/raw-ipa/commit/8432970926cecef90da3e2bf6202577950d887d6) in the file `vectorized.mpc`. The structure of the code now is quite different, and the commands below reflect the current API.


# Scaling # rows


## 2^12 4



* `/usr/bin/time --verbose python ipa compile --numrows_power=12`
* `python ipa generate_input --numrows_power=12`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 ipae2e --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 ipae2e --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 ipae2e --hostname <p0.hostname>`


## 2^13 4



* `/usr/bin/time --verbose python ipa compile --numrows_power=13`
* `python ipa generate_input --numrows_power=13`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 ipae2e --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 ipae2e --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 ipae2e --hostname <p0.hostname>`


## 2^14 4



* `/usr/bin/time --verbose python ipa compile --numrows_power=14`
* `python ipa generate_input --numrows_power=14`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 ipae2e --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 ipae2e --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 ipae2e --hostname <p0.hostname>`


## 2^15 4



* `/usr/bin/time --verbose python ipa compile --numrows_power=15`
* `python ipa generate_input --numrows_power=15`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 ipae2e --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 ipae2e --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 ipae2e --hostname <p0.hostname>`


## 2^16, 4



* `/usr/bin/time --verbose python ipa compile --numrows_power=16`
* `python ipa generate_input --numrows_power=16`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 ipae2e --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 ipae2e --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 ipae2e --hostname <p0.hostname>`


## 2^17, 4



* `/usr/bin/time --verbose python ipa compile --numrows_power=17`
* `python ipa generate_input --numrows_power=17`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 ipae2e --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 ipae2e --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 ipae2e --hostname <p0.hostname>`


## 2^18, 4



* `/usr/bin/time --verbose python ipa compile --numrows_power=18`
* `python ipa generate_input --numrows_power=18`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 ipae2e --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 ipae2e --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 ipae2e --hostname <p0.hostname>`


## 2^19, 4



* `/usr/bin/time --verbose python ipa compile --numrows_power=19`
* `python ipa generate_input --numrows_power=19`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 ipae2e --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 ipae2e --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 ipae2e --hostname <p0.hostname>`


# Measured Components Data, 2^15, 16

Arguments order:  `numrows, numbreakdowsn, n_bits, sort_type, do_sort, do_attribution, do_capping, do_aggregation`

We always used `sort_type =3` for everything which is the MP-SPDZ library radix sort.

We always used `do_capping =2` which is our parallel version of the capping algorithm.

To get the performance of each individual stage we compiled and ran with and without that individual stage and subtracted the results.


## 2^15, 16, sort only



* `/usr/bin/time --verbose python ipa compile --numrows_power=15 --breakdown_values=16 --skip_attribution --skip_capping --skip_aggregation`
* `python ipa generate_input --numrows_power=15 --breakdown_values=16`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-15-16-32-3-1-0-0-0 --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-15-16-32-3-1-0-0-0 --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-15-16-32-3-1-0-0-0 --hostname <p0.hostname>`


## 2^15, 16, sort+attribution



* `/usr/bin/time --verbose python ipa compile --numrows_power=15 --breakdown_values=16 --skip_capping --skip_aggregation`
* `python ipa generate_input --numrows_power=15 --breakdown_values=16`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-15-16-32-3-1-1-0-0 --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-15-16-32-3-1-1-0-0 --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-15-16-32-3-1-1-0-0 --hostname <p0.hostname>`


## 2^15, 16, sort+attribution+capping



* * `/usr/bin/time --verbose python ipa compile --numrows_power=15 --breakdown_values=16 --skip_aggregation`
* * `python ipa generate_input --numrows_power=15 --breakdown_values=16`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-15-16-32-3-1-1-2-0 --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-15-16-32-3-1-1-2-0 --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-15-16-32-3-1-1-2-0 --hostname <p0.hostname>`


## 2^15, 16, sort+attribution+capping+aggregation



* `/usr/bin/time --verbose python ipa compile --numrows_power=15 --breakdown_values=16 `
* `python ipa generate_input --numrows_power=15 --breakdown_values=16`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-15-16-32-3-1-1-2-1 --hostname <p0.hostname>`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-15-16-32-3-1-1-2-1 --hostname <p0.hostname>`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-15-16-32-3-1-1-2-1 --hostname <p0.hostname>`
