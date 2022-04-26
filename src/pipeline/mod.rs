pub mod async_pipe;

use crate::error::Res;

pub trait PStep {
    type Input;
    type Output;
    /// takes inputs from previous step, transforms to produce outputs for next step.
    /// # Errors
    /// If there was an unrecoverable error when processing inputs, return error and abort
    /// computation.
    fn compute(&self, inp: Self::Input) -> Res<Self::Output>;
}

/// shortcut to composing all of the steps of the pipeline.
/// takes a list of `PStep`s and feeds the outputs of one into the inputs of the next
/// final result is a function with arguments matching `Input` of the first `PStep`, and return
/// value matching `Res<Output>` of the last `PStep`.
#[macro_export]
macro_rules! build_pipeline {
    ($($step:expr)=>+) => {{
        move |res| {
            $(
                let res = $step.compute(res)?;
            )*
            Ok(res)
        }
    }};
}

pub trait Pipeline<Input, Output> {
    /// runs all steps of a given pipeline.
    /// # Errors
    /// if any steps in the pipeline fail, return that failure.
    fn pipeline(&self, inp: Input) -> Res<Output>;
}
