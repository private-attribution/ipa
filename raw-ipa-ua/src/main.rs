use std::ops::Range;
use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

mod user;

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
    ParseInt(std::num::ParseIntError),
    Length,
}
impl From<std::num::ParseIntError> for HexArgError {
    fn from(e: std::num::ParseIntError) -> Self {
        Self::ParseInt(e)
    }
}
impl ToString for HexArgError {
    fn to_string(&self) -> String {
        match self {
            Self::ParseInt(e) => e.to_string(),
            Self::Length => String::from("invalid length"),
        }
    }
}

#[derive(Debug)]
struct HexArg32(Vec<u8>);
impl FromStr for HexArg32 {
    type Err = HexArgError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        if s.as_bytes().len() != 64 {
            return Err(HexArgError::Length);
        }

        let mut buf = Vec::with_capacity(32);
        while !s.is_empty() {
            let (v, r) = s.split_at(2);
            buf.push(u8::from_str_radix(v, 16)?);
            s = r;
        }
        Ok(Self(buf))
    }
}

impl AsRef<[u8]> for HexArg32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, StructOpt)]
struct CommonArgs {
    #[structopt(short = "v", long, global = true)]
    /// Be verbose.
    verbose: bool,

    #[structopt(short = "d", long, global = true, default_value = "./ua")]
    dir: PathBuf,

    /// The first user to configure.
    #[structopt(short = "u", long, global = true, default_value = "0")]
    users: UserIds,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "action")]
enum Action {
    /// Generate configuration for client(s).
    Setup {
        /// Files containing keys for each of the helpers.
        #[structopt(number_of_values = 4)]
        helper: Vec<PathBuf>,
    },
    SetMatchKey {
        /// The origin that is setting the match key.
        domain: String,

        /// The value of the match key.
        key: HexArg32,
    },
}

impl Action {
    fn dispatch(&self, common: &CommonArgs) {
        if common.verbose {
            println!("Running {:?}", self);
        }
        assert!(common.dir.is_dir(), "UA directory (-d) not a directory");
        match self {
            Self::Setup { helper } => {
                println!("Running setup for users {:?}", common.users);
                for u in common.users {
                    let u = User::create(common.dir, u, &<[PathBuf; 4]>::try_from(helper).unwrap());
                }
            }
            Self::SetMatchKey { domain, key } => {}
        }
    }
}

fn main() {
    let args = Args::from_args();
    args.action.dispatch(&args.common);
}
