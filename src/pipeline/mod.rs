#![allow(clippy::unnecessary_fold)] // contrived example; also, `.sum()` is not implemented for stream

use futures::{FutureExt, Stream, StreamExt};

pub struct MultiplySumAndStringify {}

impl MultiplySumAndStringify {
    pub async fn run(&self, inp: impl Stream<Item = i32>) -> String {
        // chunks provides a way to buffer results as needed.
        // for instance, if deserializing a certain number of bytes, you could chunk them
        inp.chunks(2)
            // map provides a way to act on the collected chunk.
            // in this case, multiply the 2 chunked values
            .map(|v| {
                // panics if invalid number of integers in stream; must be even number
                v[0] * v[1]
            })
            // fold provides a way to accumulate all values at the end of computation.
            // in this case, sum them
            .fold(0, |acc, i| async move { acc + i })
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
        let pipe = MultiplySumAndStringify {};
        let inp = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let expected_res = inp
            .chunks(2)
            .map(|v| v[0] * v[1])
            .fold(0, |acc, i| acc + i)
            .to_string();
        let inp_stream = stream::iter(inp);
        let res = pipe.run(inp_stream).await;
        assert_eq!(expected_res, res);
    }
}
