## Benchmarks

This folder contains benchmarks for various components of IPA implementation. It will include end-to-end benchmark eventually as well. There are two different micro benchmarking frameworks used: [criterion](https://github.com/bheisler/criterion.rs) (multiplatform) and [iai](https://github.com/bheisler/iai) (Linux only). 

By convention, Criterion benchmarks have prefix `ct`, iai benchmark names start with `iai`. 

To execute a benchmark, run

```bash
cargo bench -F test-fixture --bench <benchmark_name>
```

Oneshot benchmarks are simply Rust programs that often share the benchmark logic with Criterion/iai benchmarks. They make it easier to produce and interpret flamegraphs. They may also read their input from stdin

```bash
cargo flamegraph --root --bench oneshot_arithmetic --features="test-fixture" -- --depth=64 --width=1000000       
```

Note: make sure you've installed `cargo-flamegraph` by running 

```bash
cargo add flamegraph
```