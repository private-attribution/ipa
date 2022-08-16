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

### Installation

You'll need to create a python virtual environment, and install the requirements.

```bash
python3 virtualenv ../.venv
source ../.venv/bin/activate
pip install -r ../requirements.txt
```

Note that this will also install a version of the MP-SPDZ compiler. You can also install that directly with your local copy with

```
pip install -e ../../MP-SPDZ
```

### Running IPA scripts

From this `raw-ipa/research-prototype` repository, you can now run the IPA scripts with:

```bash
python ipa
```

This will provide you with the available commands, currently `compile` and `generate_input`.

### Generate random input data

To generate random input data points, run:

```bash
python ipa generate_input
```

There are a few other options you can specify, including the size of the data, expected distribution of match keys, and even two specific test cases with expected output. Using the `-h` flag will provide all the command line options.

### Compiling the IPA MPC
The IPA protocol is primarily implemented in `raw-ipa/research-prototype/ipa/ipae2e.py`, and that implementation needs to be compiled by MP-SPDZ, to then be run with one of the various MPC backends. To run the compile step:

```bash
python ipa compile
```

Just like with `generate_input`, there are a number of arguments which can be passed in, which can all be seen with the `-h` flag. This includes skipping certain portions of the protocol to understand performance.

You can use the same arguments with both `compile` and `generate_input` (though not all are relevant.)

### Running the MPC locally

To simulate the MPC locally, run:

```bash
../../MP-SPDZ/Scripts/ring.sh -R 32 ipae2e
```

### Running the MPC on multiple hosts

Make sure you are in this directory, `raw-ipa/research-prototype`.

All hosts must use the same set of certificates for encrypted connections. Copy `Player-data/*.pem` to the `MP-SPDZ` folder on every host that will participate in MPC.

If you need private key to connect to a host (often the case for AWS cloud), here is a convenience command that does the copying (execute it from the host was used to generate gSSL certificates by running the command: `Scripts/setup-ssl.sh`)

* assume `HOST` is set to the destination host IP address or DNS name
* `MP_SDPZ_DIR` must be set to the directory where IPA is installed, for example `/home/raw-ipa/research-prototype`.

```bash
rsync -e "ssh -i <ssh cert>" -Pav Player-Data $USER@$HOST:$MP_SPDZ_DIR
```

Pick one host to be the coordinator (and player 0 by convention used by MP_SPDZ).

```bash
COORDINATOR=<host IP or DNS>
```

Run this command on the coordinator host

```bash
../../MP-SPDZ/replicated-ring-party.x --player 0 ipae2e --hostname $COORDINATOR
```

Start two other MPC parties:

host 1:
```bash
../../MP-SPDZ/replicated-ring-party.x --player 1 ipae2e --hostname $COORDINATOR
```

host 2:
```bash
../../MP-SPDZ/replicated-ring-party.x --player 1 ipae2e --hostname $COORDINATOR
```
