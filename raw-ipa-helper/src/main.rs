use log::{error, info};
use raw_ipa_cli::{HelperArgs, Verbosity};
use raw_ipa_lib::helpers::{AggregationHelper, EventHelper, Role as HelperRole};
use std::fs;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct CommonArgs {
    #[structopt(flatten)]
    /// Configure logging.
    logging: Verbosity,

    #[structopt(flatten)]
    helpers: HelperArgs,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "raw-ipa-helper", about = "Functions for IPA helper servers")]
struct Args {
    #[structopt(flatten)]
    common: CommonArgs,

    #[structopt(subcommand)]
    action: Action,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "action")]
enum Action {
    /// Generate configuration for client(s).
    Setup {
        /// The type of helper to configure.
        helper: HelperRole,
    },
}

impl Action {
    fn dispatch(&self, common: &CommonArgs) {
        match self {
            Self::Setup { helper } => {
                info!("Setup helper {}", helper);
                let dir = &common.helpers[*helper];
                if dir.exists() {
                    error!("Helper directory exists");
                    return;
                }
                fs::create_dir_all(dir).unwrap();
                match helper {
                    HelperRole::Event(r) => {
                        let h = EventHelper::new(*r);
                        h.save(dir).unwrap();
                    }
                    HelperRole::Aggregation(r) => {
                        let h = AggregationHelper::new(*r);
                        h.save(dir).unwrap();
                    }
                }
            }
        }
    }
}

fn main() {
    let args = Args::from_args();
    args.common.logging.setup_logging();
    args.action.dispatch(&args.common);
}
