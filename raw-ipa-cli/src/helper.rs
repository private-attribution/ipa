#![allow(clippy::module_name_repetitions)]

use raw_ipa_lib::helpers::{
    AggregationHelperRole, EventHelperRole, HelperLocations, Role as HelperRole,
};
use std::ops::Index;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct HelperArgs {
    /// The directory that contains source event helper files.
    #[structopt(
        long,
        visible_alias = "seh",
        global = true,
        default_value = "./db/helpers/seh"
    )]
    source_event_helper: PathBuf,

    /// The directory that contains trigger event helper files.
    #[structopt(
        long,
        visible_alias = "teh",
        global = true,
        default_value = "./db/helpers/teh"
    )]
    trigger_event_helper: PathBuf,

    /// The directory that contains the first aggregation helper files.
    #[structopt(
        long,
        visible_alias = "ah1",
        global = true,
        default_value = "./db/helpers/ah1"
    )]
    aggregation_helper1: PathBuf,

    /// The directory that contains second aggregation helper files.
    #[structopt(
        long,
        visible_alias = "ah2",
        global = true,
        default_value = "./db/helpers/ah2"
    )]
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

impl Index<HelperRole> for HelperArgs {
    type Output = Path;

    fn index(&self, index: HelperRole) -> &Self::Output {
        match index {
            HelperRole::Event(EventHelperRole::Source) => &self.source_event_helper,
            HelperRole::Event(EventHelperRole::Trigger) => &self.trigger_event_helper,
            HelperRole::Aggregation(AggregationHelperRole::Helper1) => &self.aggregation_helper1,
            HelperRole::Aggregation(AggregationHelperRole::Helper2) => &self.aggregation_helper2,
        }
    }
}
