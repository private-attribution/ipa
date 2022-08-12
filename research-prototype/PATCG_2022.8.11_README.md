
# PATCG 8/11 Benchmarks

Here are the run commands for the benchmarks we shared of IPA the the 8/11/22 PATCG. 

We ran with the 3 party honest majority malicious protocol  `sy-rep-ring-party.x` with the default statistical security of 40 bits. For semi-honest we ran replicated secret sharing protocol ‘ring.sh’

To enable mod 2^k ring computation with custom k, add `MOD = -DRING_SIZE=32` to `MP-SPDZ/CONFIG.mine` and rebuild with `make -B -j8 sy-rep-ring-party.x’ .  All of our results are were for k = 32. 

The version of the code we used is called `vectorized.mpc` and differs in how it takes arguments than the `ipae2e` version on the current main branch of raw-ipa.  The particular commit we benchmarked was [https://github.com/bmcase/raw-ipa/commit/8432970926cecef90da3e2bf6202577950d887d6](https://github.com/bmcase/raw-ipa/commit/8432970926cecef90da3e2bf6202577950d887d6) though we’ve cleaned up the comments in `vectorized.mpc` a bit since.

# Scaling # rows


## 2^12 4



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 12`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-12 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-12 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-12 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


## 2^13 4



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 13`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-13 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-13 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-13 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


## 2^14 4



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 14`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-14 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-14 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-14 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


## 2^15 4



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 15`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-15 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-15 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-15 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


## 2^16, 4



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 16 4`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-16 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-16 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-16 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


## 2^17, 4



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 17`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-17 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-17 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-17 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


## 2^18, 4



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 18`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-18 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-18 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-18 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


## 2^19, 4



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 19`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-19 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-19 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-19 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


# Measured Components Data, 2^15, 16

Arguments order:  `numrows, numbreakdowsn, n_bits, sort_type, do_sort, do_attribution, do_capping, do_aggregation`

We always used `sort_type =3` for everything which is the MP-SPDZ library radix sort. 

We always used `do_capping =2` which is our parallel version of the capping algorithm. 

To get the performance of each individual stage we compiled and ran with and without that individual stage and subtracted the results. 


## 2^15, 16, sort



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 15 16 32 3 1 0 0 0`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-15-16-32-3-1-0-0-0 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-15-16-32-3-1-0-0-0 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-15-16-32-3-1-0-0-0 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


## 2^15, 16, sort+attribution



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 15 16 32 3 1 1 0 0`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-15-16-32-3-1-1-0-0 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-15-16-32-3-1-1-0-0 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-15-16-32-3-1-1-0-0 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


## 2^15, 16, sort+attribution+capping



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 15 16 32 3 1 1 2 0`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-15-16-32-3-1-1-2-0 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-15-16-32-3-1-1-2-0 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-15-16-32-3-1-1-2-0 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`


## 2^15, 16, sort+attribution+capping+aggregation



* `/usr/bin/time --verbose ../../../MP-SPDZ/compile.py -C -R 32 vectorized 15 16 32 3 1 1 2 1`
* P0:  `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 0 vectorized-15-16-32-3-1-1-2-1 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P1: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 1 vectorized-15-16-32-3-1-1-2-1 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
* P2: `/home/ec2-user/workspace/MP-SPDZ/Scripts/../sy-rep-ring-party.x --player 2 vectorized-15-16-32-3-1-1-2-1 --hostname ec2-35-161-7-220.us-west-2.compute.amazonaws.com`
