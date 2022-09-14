use std::time::Instant;
use structopt::StructOpt;
use raw_ipa::field::{Field, Fp31};
use raw_ipa::test_fixture::circuit;

#[derive(Debug, StructOpt)]
pub struct CircuitArgs {
    #[structopt(short, long, help = "width of the circuit, defines how many operations can proceed in parallel")]
    pub width: u32,

    #[structopt(short, long, help = "depth of the circuit")]
    pub depth: u8,

    /// Cargo passes the bench argument
    /// https://doc.rust-lang.org/cargo/commands/cargo-bench.html
    #[structopt(short, long, help = "ignored")]
    pub bench: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
pub async fn main() {
    let args = CircuitArgs::from_args();

    {
        let field_size = <Fp31 as Field>::Integer::BITS;
        let width = args.width;
        let depth = args.depth;
        println!("benchmark parameters: Field size: {field_size} bits, circuit width: {width}, depth: {depth}");
    }

    let start = Instant::now();
    circuit::arithmetic::<Fp31>(args.width, args.depth).await;
    let duration = start.elapsed().as_secs_f32();

    println!("benchmark complete after {duration}s");
}