//! A pipeline describes the computation that a single helper in an MPC setting will execute. This
//! computation should be a composable series of steps, with the ability to send and receive data
//! from other helpers running their own related pipelines.
//!
//! Those looking to create their own pipeline will do so in two parts:
//!
//! * construct a series of logical [Step]s that follow one after another
//! * compose those steps as part of a [Pipeline]
//!
//! # Examples
//!
//! This example is for a single pipeline running without communication with any other pipelines. It
//! shows the most basic work you have to do to implement the [Step]s of a pipeline, and how to
//! compose those into a working [Pipeline].
//! ```
//! # use std::sync::Arc;
//! # use raw_ipa::build_pipeline;
//! # use raw_ipa::pipeline::{self, Step, Pipeline};
//! # use raw_ipa::pipeline::comms::Comms;
//! # use raw_ipa::error::Result;
//!
//! struct FirstStep{}
//! impl Step for FirstStep {
//!     type Input = (int32, int32);
//!     type Output = int32;
//!
//!     async fn compute(&self, inp: Self::Input, helper: Arc<impl Comms>) -> pipeline::Result<Self::Output> {
//!         let (x, y) = inp;
//!         x + y
//!     }
//! }
//!
//! struct SecondStep{}
//! impl Step for SecondStep {
//!     type Input = int32;
//!     type Output = String;
//!     async fn compute(&self, inp: Self::Input, helper: Arc<impl Comms>) -> pipeline::Result<Self::Output> {
//!         inp.to_string()
//!     }
//! }
//!
//! struct ExamplePipeline{}
//! impl Pipeline<(int32, int32), String> for ExamplePipeline {
//!     async fn pipeline(&self, inp: (int32, int32)) -> pipeline::Result<String> {
//!         let pipe = build_pipeline!(self.comms.clone(),
//!             FirstStep{} =>
//!             SecondStep{}
//!         );
//!         pipe(inp).await
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let example = ExamplePipeline{};
//!     let res = example.pipeline((4, 5)).await?;
//!     assert_eq!("20", res);
//!     Ok(())
//! }
//! ```
//!
//! If you need communication with other pipelines, use the `helper` argument. See [Comms](comms)
//! for more about its usage.

pub mod comms;
pub mod error;
pub mod hashmap_thread;

pub use error::Result;

use async_trait::async_trait;
use comms::Comms;
use std::sync::Arc;

/// A unit of work that makes up a part of a pipeline
#[async_trait]
pub trait Step {
    type Input;
    type Output;
    async fn compute(&self, inp: Self::Input, helper: Arc<impl Comms>) -> Result<Self::Output>;
}

/// Macro to more easily compose the steps of a pipeline
#[macro_export]
macro_rules! build_pipeline {
    ($comms:expr, $($step:expr)=>+) => {{
        move |res| async move {
            $(
                let res = $step.compute(res, $comms).await?;
            )*
            Ok(res)
        }
    }};
}

/// The higher level unit of work that describes some logical functionality of a helper that is part
/// of an MPC computation
#[async_trait]
pub trait Pipeline<Input, Output> {
    async fn pipeline(&self, inp: Input) -> Result<Output>;
}
