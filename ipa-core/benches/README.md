## Benchmarks

This folder contains benchmarks for various components of IPA implementation. It will include end-to-end benchmark eventually as well. There are two different micro benchmarking frameworks used: [criterion](https://github.com/bheisler/criterion.rs) (multiplatform) and [iai](https://github.com/bheisler/iai) (Linux only).

By convention, Criterion benchmarks have prefix `ct`, iai benchmark names start with `iai`.

To execute a benchmark, run

```bash
cargo bench -F enable-benches --bench <benchmark_name>
```

Oneshot benchmarks are simply Rust programs that often share the benchmark logic with Criterion/iai benchmarks. They make it easier to produce and interpret flamegraphs. They may also read their input from stdin

```bash
CARGO_PROFILE_BENCH_DEBUG=true cargo flamegraph --root --bench oneshot_arithmetic --features="enable-benches" -- --depth=64 --width=1000000
```

Note: make sure you've installed `cargo-flamegraph` by running

```bash
cargo add flamegraph
```

### Enabling step-level metrics

It is possible to print communication/crypto metrics with per-step breakdown. That requires default features to be turned
off.

Run the following command to print step-level metrics at the end of benchmarks. Note that debug traces impact program
performance. It is not recommended to profile IPA in this mode.

Execute the following command to enable step-level metrics. It is possible to use different bench as long as it uses
`TestWorld` to set up the environment.

```bash
RUST_LOG=ipa=DEBUG cargo bench --bench oneshot_ipa --no-default-features --features="enable-benches debug-trace compact-gate"
```

The output would look similar to this:

```
benchmark complete after 0.7891756s
Step,Records Sent,Indexed PRSS,Sequential PRSS
protocol/run-0/mc0/xor1,100,300,0
protocol/run-0/mc0/xor2,200,300,0
protocol/run-0/mc1/xor1,100,300,0
protocol/run-0/mc1/xor2,200,300,0
protocol/run-0/mc10/xor1,100,300,0
protocol/run-0/mc10/xor2,200,300,0
protocol/run-0/mc11/xor1,100,300,0
protocol/run-0/mc11/xor2,200,300,0
```

If the output is stored in a file, it is possible to derive additional metrics. For example, to compute total
number of records sent between helpers:

```bash
cat -p /tmp/steps.log | cut -d',' -f2 | awk '{s+=$1}END{print s}'
189900
```

## Memory Profiling

It is possible to profile the heap usage of IPA. We reuse `oneshot/ipa` benchmark for profiling, but any tests/executables can be profiled by enabling the global allocator. If you want more details, see DHAT [documentation](https://docs.rs/dhat/latest/dhat/).

The following command will run a benchmark and produce a profiling result.

```bash
cargo bench --bench oneshot_ipa --profile=bench-dhat --features="dhat-heap enable-benches" --no-default-features -- -n 100
```

The output will look similar to this:

```
Using random seed: 9907163113946974138 for 100 records
Preparation complete in 2.358458ms
Malicious IPA for 100 records took 96.743081542s
dhat: Total:     1,667,896,432 bytes in 11,399,291 blocks
dhat: At t-gmax: 97,081,304 bytes in 275,872 blocks
dhat: At t-end:  1,656,860 bytes in 6,836 blocks
dhat: The data has been saved to dhat-heap.json, and is viewable with dhat/dh_view.html
```

- **Total**: The total number of blocks allocated during the execution. Highly useful for evaluating heap churn; reducing the number of calls to the allocator can significantly speed up a program. This is the default sort metric.
- **At t-gmax**: This shows the breakdown of memory at the point of peak heap memory usage. Highly useful for reducing peak memory usage.
- **At t-end**: This shows the breakdown of memory at program termination. Highly useful for identifying process-lifetime leaks.

DHAT generates a file `dhat-heap.json` in the current directory. To view the results, go to https://nnethercote.github.io/dh_view/dh_view.html and upload the file.
