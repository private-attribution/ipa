use std::{
    pin::{pin, Pin},
    task::{Context, Poll},
};

use futures::{ready, Stream};
use pin_project::pin_project;

use crate::{
    error::Error,
    helpers::Message,
    protocol::{
        context::{reshard_try_stream, ShardedContext},
        RecordId,
    },
    sharding::ShardIndex,
};

type DataWithTag<D, A> = Result<(D, A), Error>;

/// Helper function to work with inputs to hybrid queries. Each encryption needs
/// to be checked for uniqueness and we use AAD tag for that. While reports are
/// being collected, AAD tags need to be resharded. This function does both at the same
/// time which should reduce the perceived latency of queries.
///
/// The output contains two separate collections: one for data and another one
/// for AAD tags that are "owned" by this shard. The tags can later be checked for
/// uniqueness.
///
/// ## Errors
/// This will return an error, if input stream contains at least one `Err` element.
#[allow(dead_code)]
pub async fn reshard_aad<L, K, A, C, S>(
    ctx: C,
    input: L,
    shard_picker: S,
) -> Result<(Vec<K>, Vec<A>), crate::error::Error>
where
    L: Stream<Item = DataWithTag<K, A>>,
    S: Fn(C, RecordId, &A) -> ShardIndex + Send,
    A: Message + Clone,
    C: ShardedContext,
{
    let mut k_buf = Vec::with_capacity(input.size_hint().1.unwrap_or(0));
    let splitter = StreamSplitter {
        inner: input,
        buf: &mut k_buf,
    };
    let a_buf = reshard_try_stream(ctx, splitter, shard_picker).await?;

    Ok((k_buf, a_buf))
}

/// Takes a fallible input stream that yields a tuple `(K, A)` and produces a new stream
/// over `A` while collecting `K` elements into the provided buffer.
/// Any error encountered from the input stream is propagated.
#[pin_project]
struct StreamSplitter<'a, S: Stream<Item = DataWithTag<K, A>>, K, A> {
    #[pin]
    inner: S,
    buf: &'a mut Vec<K>,
}

impl<S: Stream<Item = Result<(K, A), Error>>, K, A> Stream for StreamSplitter<'_, S, K, A> {
    type Item = Result<A, crate::error::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        match ready!(this.inner.poll_next(cx)) {
            Some(Ok((k, a))) => {
                this.buf.push(k);
                Poll::Ready(Some(Ok(a)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use futures::{stream, StreamExt};

    use crate::{
        error::Error,
        ff::{boolean_array::BA8, U128Conversions},
        query::runner::reshard_tag::reshard_aad,
        secret_sharing::SharedValue,
        sharding::{ShardConfiguration, ShardIndex},
        test_executor::run,
        test_fixture::{Runner, TestWorld, TestWorldConfig, WithShards},
    };

    #[test]
    fn reshard_basic() {
        run(|| async {
            let world: TestWorld<WithShards<2>> =
                TestWorld::with_shards(TestWorldConfig::default());
            world
                .malicious(
                    vec![BA8::truncate_from(1u128), BA8::truncate_from(2u128)].into_iter(),
                    |ctx, input| async move {
                        let shard_id = ctx.shard_id();
                        let sz = input.len();
                        let (values, tags) = reshard_aad(
                            ctx,
                            stream::iter(input).map(|v| Ok((v, BA8::ZERO))),
                            |_, _, _| ShardIndex::FIRST,
                        )
                        .await
                        .unwrap();
                        assert_eq!(sz, values.len());
                        match shard_id {
                            ShardIndex::FIRST => assert_eq!(2, tags.len()),
                            _ => assert_eq!(0, tags.len()),
                        }
                    },
                )
                .await;
        });
    }

    #[test]
    #[should_panic(expected = "InconsistentShares")]
    fn reshard_err() {
        run(|| async {
            let world: TestWorld<WithShards<2>> =
                TestWorld::with_shards(TestWorldConfig::default());
            world
                .malicious(
                    vec![BA8::truncate_from(1u128), BA8::truncate_from(2u128)].into_iter(),
                    |ctx, input| async move {
                        reshard_aad(
                            ctx,
                            stream::iter(input)
                                .map(|_| Err::<(BA8, BA8), _>(Error::InconsistentShares)),
                            |_, _, _| ShardIndex::FIRST,
                        )
                        .await
                        .unwrap();
                    },
                )
                .await;
        });
    }
}
