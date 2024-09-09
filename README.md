# IPA

A collaborative effort to create prototype of the helper (or server) components
of the [Interoperable Private Attribution (IPA)
proposal](https://github.com/patcg-individual-drafts/ipa/).

IPA enables
[attribution](https://en.wikipedia.org/wiki/Attribution_(marketing)), providing
information about how advertising campaigns are delivering value to advertisers,
while giving users strong privacy assurances.  IPA uses multi-party computation
(MPC) to achieve this goal.  IPA relies on three helper nodes (servers) that are
trusted to faithfully execute the protocol without conspiring with other helper
nodes to violate user privacy.

## This Project

This project is intended to be a functional, performant, and comprehensible
implementation of the core IPA protocol.  This should allow for validation of
the implementation and should enable performance measurement.

The eventual goal is to provide the core of an implementation that could be
deployed and used.  This will require additional infrastructure in order to meet
the privacy and security goals of the project.

This is very much a work in progress; input is welcome.  However, see our
[contribution guidelines](./CONTRIBUTING.md) for some important notices
regarding how to participate in the project.

## Getting Started

### Installation

First, clone this repo. If you have the [GitHub CLI](https://cli.github.com/manual/installation) installed:

```
gh repo clone private-attribution/ipa && cd ipa
```

or just with Git:

```
git clone https://github.com/private-attribution/ipa && cd ipa
```

Check to make sure you have a recent version of Rust with

```
rustc -V
```

If you do not have Rust installed, see the [rust-lang instructions](https://www.rust-lang.org/tools/install).

### Building IPA

To build the project, run:

```
cargo build
```

The first time, it will download the necessary packages (crates) and compile the project.

If you're just running tests/benchmarks, it will build automatically and you can skip this step.

If you want to get a helper binary, here's an example command showcasing some of the available features:

```
cargo build --bin helper --features='web-app real-world-infra compact-gate multi-threading disable-metrics stall-detection' --no-default-features --release
```

### Building IPA as a Docker Image

To build a docker image with IPA helper in it:

```
docker build -t ipa:latest -f docker/helper.Dockerfile .
```

Note that if you want to build for a specific platform, different than the one you're using, you need to specify it. For example:

```
docker build -t ipa:latest --platform=linux/amd64 -f docker/helper.Dockerfile .
```

### Pushing Docker to ghcr.io

First, follow the instructions [here](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry) to get your Token.

```
echo $CR_PAT | docker login ghcr.io -u <USER_NAME> --password-stdin
docker tag <IMAGE_ID> ghcr.io/private-attribution/ipa/ipa-helper:<TAG>
docker push ghcr.io/private-attribution/ipa/ipa-helper:<TAG>
```

### Running tests

To run the test suite, run

```
cargo test
```

### Running Benchmarks

There are a handful of benchmarks which can be run, but `oneshot_ipa` will run the whole protocol locally. On a M1 Macbook Pro, this takes a couple minutes.

```
cargo bench --bench oneshot_ipa --no-default-features --features="enable-benches compact-gate"
```

Other benchmarks you can run:

**Sorting**:
```
cargo bench --bench oneshot_sort --no-default-features --features="enable-benches compact-gate"
```

**Arithmetic gates**:
```
cargo bench --bench oneshot_arithmetic --no-default-features --features="enable-benches compact-gate" -- --width 1 --depth 1
```
You can adjust the width and depth of the gates at the expense of a longer benchmarking run.

**Varying the DP Parameters**:
You can run with DP for outputs and a custom epsilon. 
```
cargo bench --bench oneshot_ipa --no-default-features --features="enable-benches compact-gate" -- --with-dp 1 --epsilon 3.0
```
You can run without DP for outputs. 
```
cargo bench --bench oneshot_ipa --no-default-features --features="enable-benches compact-gate" -- --with-dp 0 
```

**Other**:
```
cargo bench --bench criterion_arithmetic --no-default-features --features="enable-benches compact-gate"
```

```
cargo bench --bench iai_arithmetic --no-default-features --features="enable-benches compact-gate"
```
(NOTE: This benchmark only works on Linux. If you are on macOS, an error is expected.)
