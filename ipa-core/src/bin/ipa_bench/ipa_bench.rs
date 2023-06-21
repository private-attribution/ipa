mod cmd;
mod config;
mod gen_events;
mod models;
mod sample;

use clap::Parser;

fn main() {
    let args = cmd::Args::parse();
    let _handle = args.common.logging.setup_logging();
    args.cmd.dispatch(&args.common);
}
