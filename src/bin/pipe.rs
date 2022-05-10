/// this file is for demonstration purposes. I plan to delete it before merging anything, but it's
/// a good way to show off some ideas for review
use raw_ipa::build_pipeline;
use raw_ipa::error::Res;
use raw_ipa::pipeline::{PStep, Pipeline};

/// Takes no inputs, and produces a hard-coded tuple value.
/// Meant to be the first step in the pipeline
struct Start {
    x: i32,
    y: i32,
}
impl PStep for Start {
    type Input = ();
    type Output = (i32, i32);

    fn compute(&self, _: Self::Input) -> Res<Self::Output> {
        Ok((self.x, self.y))
    }
}
/// Takes 2 inputs, adds them together and produce one output
struct Add {}
impl PStep for Add {
    type Input = (i32, i32);
    type Output = i32;

    fn compute(&self, inp: Self::Input) -> Res<Self::Output> {
        Ok(inp.0 + inp.1)
    }
}
/// Takes 1 input, divides it in half, and returns both halves as output
/// trivial work to show that types can change between steps of the pipeline
struct Split {}
impl PStep for Split {
    type Input = i32;
    type Output = (i32, i32);

    fn compute(&self, inp: Self::Input) -> Res<Self::Output> {
        let half = inp / 2;
        Ok((half, inp - half))
    }
}

struct ExamplePipeline {}
impl Pipeline<(), i32> for ExamplePipeline {
    fn pipeline(&self, inp: ()) -> Res<i32> {
        // usage of build_pipeline! that produces a `Fn(()) -> Res<i32>`
        let finally = build_pipeline!(Start { x: 1, y: 2 } => Add {} => Split {} => Add {});
        finally(inp)
    }
}

fn main() -> Res<()> {
    let example = ExamplePipeline {};
    example.pipeline(()).map(|res| println!("{res}"))
}
