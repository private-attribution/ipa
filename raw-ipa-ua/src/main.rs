use hex::{self, FromHexError};
use raw_ipa_lib::{helpers::Helpers, user::User};
use std::convert::TryFrom;
use std::fs;
use std::mem;
use std::ops::Range;
use std::path::PathBuf;
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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((start, end)) = s.split_once("..") {
            let start = if start.is_empty() { 0 } else { start.parse()? };
            let (incr, end) = if let Some(e) = end.strip_prefix('=') {
                (true, e)
            } else {
                (false, end)
            };
            Ok(Self(start..end.parse::<usize>()? + usize::from(incr)))
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

    #[structopt(short = "d", long, global = true, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../db/ua"))]
    dir: PathBuf,

    /// The first user to configure.
    #[structopt(
        short = "u",
        long,
        global = true,
        default_value = "0",
        multiple = true,
        use_delimiter = true
    )]
    users: Vec<UserIds>,
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
    Setup {
        /// Files containing keys for each of the helpers.
        #[structopt(number_of_values = 4)]
        helpers: Vec<PathBuf>,
    },
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
            Self::Setup { helpers } => {
                if !common.dir.is_dir() {
                    println!("Create directory {}", common.dir.to_string_lossy());
                    fs::create_dir_all(&common.dir).unwrap();
                }

                let helpers = Helpers::load(&*helpers).unwrap();
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
                    let mut u = User::load(&common.dir, u).unwrap();
                    u.set_matchkey(origin, key.as_ref());
                    u.save(&common.dir).unwrap();
                }
            }
        }
    }
}

fn main() {
    let args = Args::from_args();
    args.action.dispatch(&args.common);
}
