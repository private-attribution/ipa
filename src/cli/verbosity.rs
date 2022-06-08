use log::info;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Verbosity {
    /// Silence all output
    #[structopt(short = "q", long = "quiet", global = true)]
    quiet: bool,

    /// Verbose mode (-v, -vv, -vvv, etc)
    #[structopt(short = "v", long = "verbose", global = true, parse(from_occurrences))]
    verbose: usize,
}

impl Verbosity {
    pub fn setup_logging(&self) {
        stderrlog::new()
            .quiet(self.quiet)
            .verbosity(self.verbose)
            .timestamp(stderrlog::Timestamp::Off)
            .init()
            .unwrap_or_else(|e| {
                if !self.quiet {
                    eprintln!("unable to configure logging: {:?}", e);
                }
            });
        info!("Logging setup at level {}", log::max_level());
    }
}
