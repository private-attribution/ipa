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
//! # use tokio::sync::mpsc;
//! # use raw_ipa::pipeline::comms;
//! # use rand::{thread_rng, Rng};
//! use async_trait::async_trait;
//! use std::sync::Arc;
//! use raw_ipa::build_pipeline;
//! use raw_ipa::pipeline::{self, Step, Pipeline};
//! use raw_ipa::pipeline::comms::buffer;
//! use raw_ipa::pipeline::comms::Comms;
//! use raw_ipa::error::Result;
//!
//! struct FirstStep{}
//! #[async_trait]
//! impl Step for FirstStep {
//!     type Input = (i32, i32);
//!     type Output = i32;
//!
//!     async fn compute(&self, inp: Self::Input, helper: Arc<impl Comms>) -> pipeline::Result<Self::Output> {
//!         let (x, y) = inp;
//!         Ok(x + y)
//!     }
//! }
//!
//! struct SecondStep{}
//! #[async_trait]
//! impl Step for SecondStep {
//!     type Input = i32;
//!     type Output = String;
//!     async fn compute(&self, inp: Self::Input, helper: Arc<impl Comms>) -> pipeline::Result<Self::Output> {
//!         Ok(inp.to_string())
//!     }
//! }
//!
//! struct ExamplePipeline{
//!     comms: Arc<comms::Channel<buffer::Mem>>
//! }
//! #[async_trait]
//! impl Pipeline<(i32, i32), String> for ExamplePipeline {
//!     async fn pipeline(&self, inp: (i32, i32)) -> pipeline::Result<String> {
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
//! #   let shared_id = thread_rng().gen();
//! #   let (next_send, _) = mpsc::channel(32);
//! #   let (prev_send, _) = mpsc::channel(32);
//! #   let buffer = buffer::Mem::new("example_buffer");
//! #   let comms = Arc::new(comms::Channel::new("example_comms", next_send, prev_send, buffer, shared_id));
//!     // `comms` definition omitted here
//!     let example = ExamplePipeline{ comms };
//!     let res = example.pipeline((4, 5)).await?;
//!     assert_eq!("9", res);
//!     Ok(())
//! }
//! ```
//!
//! If you need communication with other pipelines, use the `helper` argument. See [Comms](comms)
//! for more about its usage.

pub mod comms;
pub mod error;
pub mod util;

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
