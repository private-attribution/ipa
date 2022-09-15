mod cmd;
mod config;
mod gen_events;
mod models;
mod net;
mod sample;

use structopt::StructOpt;

fn main() {
    let args = cmd::Args::from_args();
    args.common.logging.setup_logging();
    args.cmd.dispatch(&args.common);
}
