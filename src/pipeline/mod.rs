#![allow(clippy::unnecessary_fold)] // contrived example; also, `.sum()` is not implemented for stream

use futures::{FutureExt, Stream, StreamExt};

// this is the first of a pair of pipelines to process a stream of data
// in this stage, simply pair up values, then multiply them together
// the output of this pipeline is a stream, to be consumed by the next pipeline
pub struct PairAndMultiplyPipeline {}
impl PairAndMultiplyPipeline {
    pub fn run(&self, inp: impl Stream<Item = i32>) -> impl Stream<Item = i32> {
        // chunks provides a way to buffer results as needed.
        // for instance, if deserializing a certain number of bytes, you could chunk them
        inp.chunks(2)
            // map provides a way to act on the collected chunk.
            // in this case, multiply the 2 chunked values
            .map(|v| {
                // panics if invalid number of integers in stream; must be even number
                v[0] * v[1]
            })
    }
}

// this is the second of a pair of pipelines to process a stream of data.
// in this stage, sum all values, and then to_string() the final sum.
// the output of this pipeline is a string of the sum
pub struct SumAndStringifyPipeline {}
impl SumAndStringifyPipeline {
    pub async fn run(&self, inp: impl Stream<Item = i32>) -> String {
        // fold provides a way to accumulate all values at the end of computation.
        // in this case, sum them
        inp.fold(0, |acc, i| async move { acc + i })
            // finally, it is possible to further work on the value, since it is within a future.
            // alternatively, just `await` the future and act on the value at that time.
            // in this case, stringify
            .map(|i| i.to_string())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    #[tokio::test]
    async fn usage() {
        let inp = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let expected_res = inp
            .chunks(2)
            .map(|v| v[0] * v[1])
            .fold(0, |acc, i| acc + i)
            .to_string();
        let inp_stream = stream::iter(inp);

        // combine both pipelines to produce the final output.
        // we could do a couple things to make this easier,
        // for instance, have a `compose` macro a la haskell:
        // https://wiki.haskell.org/Function_composition
        let pipe1 = PairAndMultiplyPipeline {};
        let pipe2 = SumAndStringifyPipeline {};
        let res1 = pipe1.run(inp_stream);
        let res2 = pipe2.run(res1).await;
        assert_eq!(expected_res, res2);
    }
}
