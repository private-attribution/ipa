mod cmd;
mod gen;

use structopt::StructOpt;

fn main() {
    let args = cmd::Args::from_args();
    args.common.logging.setup_logging();
    args.cmd.dispatch(&args.common);
}
