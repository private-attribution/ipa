# IPA End-2-End Prototype in MP-SPDZ

This is a prototype of IPA, written in the research MPC system, [MP-SPDZ](https://github.com/data61/MP-SPDZ).


## Installation

To run the prototype, you will need to clone the MP-SPDZ repo so that it neighbors the `raw-ipa` repo.

From the current directory (i.e. `raw-ipa/research-prototype`)

```bash
cd ../..
gh repo clone data61/MP-SPDZ
cd MP-SPDZ

```

Then, to setup MP-SPDZ, run:

```bash
make -j 8 tldr
```

On a Mac, this requires brew to be installed, and on Linux it requires other certain packages to be installed. See the [MP-SPDZ README](https://github.com/data61/MP-SPDZ#tldr-source-distribution) for more details.

This prototype uses the `replicated-ring-party.x` MP-SPDZ virtual machine. To compile, make sure you're still in the `MP-SPDZ` directory. First, we need to compile a 32 bit ring, so we need to add one more config to `CONFIG.mine` by running:

```bash
echo "MOD = -DRING_SIZE=32" >> CONFIG.mine
```

Then, to compile, run:
```bash
make clean -B -j 8 replicated-ring-party.x
```

Finally, you'll need to setup SSL for the parties. From the `raw-ipa/research-prototype` directory, run:

```bash
../../MP-SPDZ/Scripts/setup-ssl.sh 3
```

## Running the Prototype

Make sure you are now back in this directory, `raw-ipa/research-prototype`.


### Generate random input data

To generate 2^10 random input data points, run:

```bash
python3 ipainput.py 10
```

If you'd like to generate more, replace 10 with N to generate 2^N data points.

### Compiling the IPA MPC
To run the compiler:

```bash
../../MP-SPDZ/compile.py -C -R 32 ipae2e
```

There are two options (specific to the IPA prototype) that you can provide as environmental variables: `IPA_VERBOSE` and `IPA_NUMROWS_POWER`. (The MP-SPDZ compile script consumes command line args, hence the need for environmental variables.) An example of providing these for a single compile step:

```bash
IPA_VERBOSE=True IPA_NUMROWS_POWER=5 ../../MP-SPDZ/compile.py -C -R 32 ipae2e
```

Note that you should also generate random data accordingly. Also, to avoid dumping way to much data into your terminal, you cannot use the verbose mode for more than 2^5 rows.

### Running the MPC locally

To simulate the MPC locally, run:

```bash
../../MP-SPDZ/Scripts/ring.sh -R 32 ipae2e
```

### Running the MPC on multiple hosts

Make sure you are in this directory, `raw-ipa/research-prototype`.

All hosts must use the same set of certificates for encrypted connections. Copy `Player-data/*.pem` to the `MP-SPDZ`
folder on every host that will participate in MPC. 

If you need private key to connect to a host (often the case for AWS cloud), here is a convenience command that does 
the copying (execute it from the host was used to generate SSL certificates by running the command: `Scripts/setup-ssl.sh`)

* assume `HOST` is set to the destination host IP address or DNS name
* `MP_SDPZ_DIR` must be set to the directory where IPA is installed, for example `/home/raw-ipa/research-prototype`.

```bash
rsync -e "ssh -i <ssh cert>" -Pav Player-Data $USER@$HOST:$MP_SPDZ_DIR
```

Pick one host to be the coordinator (and player 0 by convention used by MP_SPDZ).

```bash
export $COORDINATOR=<host IP or DNS>
```

Run this command on the coordinator host

```bash
../../MP-SPDZ/Scripts/../replicated-ring-party.x --player 0 ipae2e --hostname $COORDINATOR
```

Start two other MPC parties:

host 1:
```bash
../../MP-SPDZ/Scripts/../replicated-ring-party.x --player 1 ipae2e --hostname $COORDINATOR
```

host 2:
```bash
../../MP-SPDZ/Scripts/../replicated-ring-party.x --player 1 ipae2e --hostname $COORDINATOR
```
