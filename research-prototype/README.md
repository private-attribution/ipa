# IPA End-2-End Prototype in MP-SPDZ

This is a prototype of IPA, written in the research MPC system, [MP-SPDZ](https://github.com/data61/MP-SPDZ).


## Installation

To run the prototype, you will need to clone the MP-SPDZ repo 

On a Mac, this requires brew to be installed, and on Linux it requires other certain packages to be installed. See the [MP-SPDZ README](https://github.com/data61/MP-SPDZ#tldr-source-distribution) for more details.

On a Mac, if your homebrew is installed in a non-traditional location, see [this issue.](https://github.com/data61/MP-SPDZ/pull/628).

To clone run

```
gh repo clone data61/MP-SPDZ
cd MP-SPDZ

```

Then, to setup MP-SPDZ, run:

```
make -j 8 tldr
```

To run your code in the MP-SPDZ directory, place the circuit files `.mpc` in `MP-SPDZ/Programs/Source` and your input files in `MP-SPDZ/Player-Data/` (you may need to create this folder). 

To generate an input file you can run `python createinput.py` in `Player-Data`

One MPC protocol this program can be run with is the the honest majority semi-honest `replicated-ring-party.x`. To compile, make sure you're still in the `MP-SPDZ` directory. First, we will add a custom ring size 2^32, so we need to add one more config to `CONFIG.mine` by running:

```
echo "MOD = -DRING_SIZE=32" >> CONFIG.mine
```

Then, to build the MPC virtual machine, run:
```
make clean -B -j 8 replicated-ring-party.x
```

## Compiling the circuit

To compile the circuit, in the top `MP-SPDZ` folder run 
```
./compile.py -C -R 32 ipae2e2048
```

`R -32` tells it to compile for the ring of integers mod 2^32. `-C` is a optimization flag for the compiler.

In the output you see will the number of "integer triples" corresponds to the number of multiplication gates in the circuit and the number of "virtual machine rounds" corresponds to the multiplication depth of the circuit. 

e.g. for this `ipae2e2048.mpc` code you should see the generated circuit has 7,431,398 multiplications and a depth of 132. 
## Running the MPC
From the top `MP-SPZ` directory, if this is your first time to run the protocol you'll need to setup SSL for 3 parties by running 
```Scripts/setup-ssl.sh 3```

then run the MPC with 
```Scripts/ring.sh -R 32 ipae2e```








