use std::time::Instant;

use clap::Parser;
use ipa_core::{ff::Fp31, secret_sharing::SharedValue, test_fixture::circuit};

#[derive(Debug, Parser)]
pub struct CircuitArgs {
    #[arg(
        short,
        long,
        help = "width of the circuit, defines how many operations can proceed in parallel",
        default_value_t = 10
    )]
    pub width: u32,

    #[arg(short, long, help = "depth of the circuit", default_value_t = 10)]
    pub depth: u16,

    /// Cargo passes the bench argument
    /// https://doc.rust-lang.org/cargo/commands/cargo-bench.html
    #[arg(short, long, help = "ignored")]
    pub bench: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
pub async fn main() {
    let args = CircuitArgs::parse();

    {
        let field_size = Fp31::BITS;
        let width = args.width;
        let depth = args.depth;
        println!(
            "benchmark parameters: Field size: {field_size} bits, circuit width: {width}, depth: {depth}"
        );
    }

    let input = circuit::arithmetic_setup(args.width, args.depth);
    let start = Instant::now();
    circuit::arithmetic::<Fp31, 1>(args.width, args.depth, 1024, input).await;
    let duration = start.elapsed().as_secs_f32();

    println!("benchmark complete after {duration}s");
}
