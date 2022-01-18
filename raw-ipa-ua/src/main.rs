use log::{debug, error, info, trace, warn};
use raw_ipa_cli::{HelperArgs, HexArg, Verbosity};
use raw_ipa_lib::{helpers::Helpers, user::User};
use std::fs;
use std::ops::Range;
use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "raw-ipa-ua", about = "Functions for IPA User Agents")]
struct Args {
    #[structopt(flatten)]
    common: CommonArgs,

    #[structopt(subcommand)]
    action: Action,
}

#[derive(Debug)]
struct UserIds(Range<usize>);
impl FromStr for UserIds {
    type Err = <usize as FromStr>::Err;

    #[allow(clippy::range_plus_one)] // Target type is not RangeInclusive.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((start, end)) = s.split_once("..") {
            let start = if start.is_empty() { 0 } else { start.parse()? };
            let (incl, end) = if let Some(e) = end.strip_prefix('=') {
                (true, e.parse::<usize>()?)
            } else {
                (false, end.parse::<usize>()?)
            };
            if start == end && !incl {
                warn!("Warning: user range {} is empty", s);
            }
            Ok(Self(start..end + usize::from(incl)))
        } else {
            let v = s.parse()?;
            Ok(Self(v..v + 1))
        }
    }
}

#[derive(Debug, StructOpt)]
struct CommonArgs {
    #[structopt(flatten)]
    /// Configure logging.
    logging: Verbosity,

    #[structopt(short = "d", long, global = true, default_value = "./db/ua")]
    dir: PathBuf,

    /// The set of user IDs to configure.
    #[structopt(
        short = "u",
        long,
        global = true,
        default_value = "0",
        multiple = true,
        use_delimiter = true
    )]
    users: Vec<UserIds>,

    #[structopt(flatten)]
    helpers: HelperArgs,
}

impl CommonArgs {
    fn all_users(&self) -> impl Iterator<Item = usize> + '_ {
        self.users.iter().flat_map(|r| r.0.clone())
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "action")]
enum Action {
    /// Generate configuration for client(s).
    Setup,
    /// Set a match key for a particular origin/domain.
    SetMatchKey {
        /// The origin that is setting the match key.
        origin: String,

        /// The value of the match key.
        key: HexArg<32>,
    },
}

impl Action {
    fn dispatch(&self, common: &CommonArgs) {
        info!("Running {:?}", self);
        match self {
            Self::Setup => {
                if !common.dir.is_dir() {
                    debug!("Create directory {}", common.dir.to_string_lossy());
                    fs::create_dir_all(&common.dir).unwrap();
                }

                let helpers = Helpers::load(&common.helpers).unwrap();
                for uid in common.all_users() {
                    trace!("Create user {}", uid);

                    let u = User::new(uid, helpers.matchkey_encryption_key());
                    if u.filename(&common.dir).exists() {
                        warn!("File for user {} exists", uid);
                    } else {
                        u.save(&common.dir).unwrap();
                    }
                }
            }
            Self::SetMatchKey { origin, key } => {
                info!(
                    "Set matchkey for origin {} to {}",
                    origin,
                    hex::encode(key.as_ref())
                );
                for uid in common.all_users() {
                    trace!("Set matchkey for user {}", uid);
                    if let Ok(mut u) = User::load(&common.dir, uid) {
                        u.set_matchkey(origin, key.as_ref());
                        u.save(&common.dir).unwrap();
                    } else {
                        error!("Error loading user {}, run setup?", uid);
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
