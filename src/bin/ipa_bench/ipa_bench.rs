mod cmd;
mod config;
mod gen_events;
mod sample;

use structopt::StructOpt;

fn main() {
    let args = cmd::Args::from_args();
    let _handle = args.common.logging.setup_logging();
    args.cmd.dispatch(&args.common);
}
