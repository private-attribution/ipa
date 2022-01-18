use hex::{self, FromHexError};
use raw_ipa_lib::helpers::HelperLocations;
use raw_ipa_lib::{helpers::Helpers, user::User};
use std::convert::TryFrom;
use std::fs;
use std::mem;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "raw-ipa-ua",
    about = "User Agent functions for demonstration purposes"
)]
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
                eprintln!("Warning: user range {} is empty", s);
            }
            Ok(Self(start..end + usize::from(incl)))
        } else {
            let v = s.parse()?;
            Ok(Self(v..v + 1))
        }
    }
}

#[derive(Debug)]
enum HexArgError {
    Hex(FromHexError),
    Length,
}
impl From<FromHexError> for HexArgError {
    fn from(e: FromHexError) -> Self {
        Self::Hex(e)
    }
}
impl From<Vec<u8>> for HexArgError {
    fn from(_: Vec<u8>) -> Self {
        Self::Length
    }
}
impl ToString for HexArgError {
    fn to_string(&self) -> String {
        match self {
            Self::Hex(e) => e.to_string(),
            Self::Length => String::from("invalid length"),
        }
    }
}

#[derive(Debug)]
struct HexArg32([u8; 32]);
impl FromStr for HexArg32 {
    type Err = HexArgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = hex::decode(s)?;
        let v = <[u8; 32]>::try_from(b)?;
        Ok(Self(v))
    }
}

impl AsRef<[u8; 32]> for HexArg32 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, StructOpt)]
struct CommonArgs {
    #[structopt(short = "v", long, global = true)]
    /// Be verbose.
    verbose: bool,

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
struct HelperArgs {
    /// The directory that contains source event helper files.
    #[structopt(long, alias = "seh", global = true, default_value = "./db/helpers/seh")]
    source_event_helper: PathBuf,

    /// The directory that contains trigger event helper files.
    #[structopt(long, alias = "teh", global = true, default_value = "./db/helpers/teh")]
    trigger_event_helper: PathBuf,

    /// The directory that contains the first aggregation helper files.
    #[structopt(long, alias = "ah1", global = true, default_value = "./db/helpers/ah1")]
    aggregation_helper1: PathBuf,

    /// The directory that contains second aggregation helper files.
    #[structopt(long, alias = "ah2", global = true, default_value = "./db/helpers/ah2")]
    aggregation_helper2: PathBuf,
}

impl HelperLocations for HelperArgs {
    fn source_event(&self) -> &Path {
        &self.source_event_helper
    }
    fn trigger_event(&self) -> &Path {
        &self.trigger_event_helper
    }
    fn aggregation1(&self) -> &Path {
        &self.aggregation_helper1
    }
    fn aggregation2(&self) -> &Path {
        &self.aggregation_helper2
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
        key: HexArg32,
    },
}

impl Action {
    fn dispatch(&self, common: &CommonArgs) {
        if common.verbose {
            println!("Running {:?}", self);
        }
        match self {
            Self::Setup => {
                if !common.dir.is_dir() {
                    println!("Create directory {}", common.dir.to_string_lossy());
                    fs::create_dir_all(&common.dir).unwrap();
                }

                let helpers = Helpers::load(&common.helpers).unwrap();
                for u in common.all_users() {
                    if common.verbose {
                        println!("Create user {}", u);
                    }

                    mem::drop(User::create(
                        &common.dir,
                        u,
                        helpers.matchkey_encryption_key(),
                    ));
                }
            }
            Self::SetMatchKey { origin, key } => {
                if common.verbose {
                    println!(
                        "Set matchkey for origin {} to {}",
                        origin,
                        hex::encode(key.as_ref())
                    );
                }
                for u in common.all_users() {
                    if common.verbose {
                        println!("Set matchkey for user {}", u);
                    }
                    if let Ok(mut u) = User::load(&common.dir, u) {
                        u.set_matchkey(origin, key.as_ref());
                        u.save(&common.dir).unwrap();
                    } else {
                        eprintln!("Error loading user {}, run setup?", u);
                    }
                }
            }
        }
    }
}

fn main() {
    let args = Args::from_args();
    args.action.dispatch(&args.common);
}
