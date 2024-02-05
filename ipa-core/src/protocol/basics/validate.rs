use std::{
    convert::Infallible,
    marker::PhantomData,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use futures::{
    future::try_join,
    stream::{Fuse, Stream, StreamExt},
    Future, FutureExt,
};
use generic_array::GenericArray;
use pin_project::pin_project;
use sha2::{
    digest::{typenum::Unsigned, FixedOutput, OutputSizeUser},
    Digest, Sha256,
};

use crate::{
    error::Error,
    ff::Serializable,
    helpers::{Direction, Message},
    protocol::{context::Context, RecordId},
    secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
    seq_join::assert_send,
};

type HashFunction = Sha256;
type HashSize = <HashFunction as OutputSizeUser>::OutputSize;
type HashOutputArray = [u8; <HashSize as Unsigned>::USIZE];

#[derive(Debug, Clone, PartialEq, Eq)]
struct HashValue(GenericArray<u8, HashSize>);

impl Serializable for HashValue {
    type Size = HashSize;
    type DeserializationError = Infallible;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(self.0.as_slice());
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        Ok(Self(buf.to_owned()))
    }
}

impl Message for HashValue {}

impl From<HashFunction> for HashValue {
    fn from(value: HashFunction) -> Self {
        // Ugh: The version of sha2 we currently use doesn't use the same GenericArray version as we do.
        HashValue(GenericArray::from(<HashOutputArray>::from(
            value.finalize_fixed(),
        )))
    }
}

struct ReplicatedValidatorFinalization {
    f: Pin<Box<(dyn Future<Output = Result<(), Error>> + Send)>>,
}

impl ReplicatedValidatorFinalization {
    fn new<C: Context + 'static>(active: ReplicatedValidatorActive<C>) -> Self {
        let ReplicatedValidatorActive {
            ctx,
            left_hash,
            right_hash,
        } = active;
        let left_hash = HashValue::from(left_hash);
        let right_hash = HashValue::from(right_hash);
        let left_peer = ctx.role().peer(Direction::Left);
        let right_peer = ctx.role().peer(Direction::Right);

        let f = Box::pin(assert_send(async move {
            try_join(
                ctx.send_channel(left_peer)
                    .send(RecordId::FIRST, left_hash.clone()),
                ctx.send_channel(right_peer)
                    .send(RecordId::FIRST, right_hash.clone()),
            )
            .await?;
            let (left_recvd, right_recvd) = try_join(
                ctx.recv_channel(left_peer).receive(RecordId::FIRST),
                ctx.recv_channel(right_peer).receive(RecordId::FIRST),
            )
            .await?;
            if left_hash == left_recvd && right_hash == right_recvd {
                Ok(())
            } else {
                Err(Error::Internal) // TODO add a code
            }
        }));
        Self { f }
    }

    fn poll(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        self.f.poll_unpin(cx)
    }
}

struct ReplicatedValidatorActive<C> {
    ctx: C,
    left_hash: Sha256,
    right_hash: Sha256,
}

impl<C: Context + 'static> ReplicatedValidatorActive<C> {
    fn new(ctx: C) -> Self {
        Self {
            ctx,
            left_hash: HashFunction::new(),
            right_hash: HashFunction::new(),
        }
    }

    fn update<S, V>(&mut self, s: &S)
    where
        S: ReplicatedSecretSharing<V>,
        V: SharedValue,
    {
        let mut buf = GenericArray::default(); // ::<u8, <V as Serializable>::Size>
        s.left().serialize(&mut buf);
        self.left_hash.update(buf.as_slice());
        s.right().serialize(&mut buf);
        self.right_hash.update(buf.as_slice());
    }

    fn finalize(self) -> ReplicatedValidatorFinalization {
        ReplicatedValidatorFinalization::new(self)
    }
}

enum ReplicatedValidatorState<C> {
    /// While the validator is waiting, it holds a context reference.
    Pending(Option<Box<ReplicatedValidatorActive<C>>>),
    /// After the validator has taken all of its inputs, it holds a future.
    Finalizing(ReplicatedValidatorFinalization),
}

impl<C: Context + 'static> ReplicatedValidatorState<C> {
    /// # Panics
    /// This panics if it is called after `finalize()`.
    fn update<S, V>(&mut self, s: &S)
    where
        S: ReplicatedSecretSharing<V>,
        V: SharedValue,
    {
        if let Self::Pending(Some(a)) = self {
            a.update(s);
        } else {
            panic!();
        }
    }

    fn poll(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        match self {
            Self::Pending(ref mut active) => {
                let mut f = active.take().unwrap().finalize();
                let res = f.poll(cx);
                *self = ReplicatedValidatorState::Finalizing(f);
                res
            }
            Self::Finalizing(f) => f.poll(cx),
        }
    }
}

#[pin_project]
struct ReplicatedValidator<C, T: Stream, S, V> {
    #[pin]
    input: Fuse<T>,
    state: ReplicatedValidatorState<C>,
    _marker: PhantomData<(S, V)>,
}

impl<C: Context + 'static, T: Stream, S, V> ReplicatedValidator<C, T, S, V> {
    pub fn new(ctx: C, s: T) -> Self {
        Self {
            input: s.fuse(),
            state: ReplicatedValidatorState::Pending(Some(Box::new(
                ReplicatedValidatorActive::new(ctx),
            ))),
            _marker: PhantomData,
        }
    }
}

impl<C, T, S, V> Stream for ReplicatedValidator<C, T, S, V>
where
    C: Context + 'static,
    T: Stream<Item = Result<S, Error>>,
    S: ReplicatedSecretSharing<V>,
    V: SharedValue,
{
    type Item = Result<S, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        match this.input.poll_next(cx) {
            Poll::Ready(Some(v)) => match v {
                Ok(v) => {
                    this.state.update(&v);
                    Poll::Ready(Some(Ok(v)))
                }
                Err(e) => Poll::Ready(Some(Err(e))),
            },
            Poll::Ready(None) => match this.state.poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) => Poll::Ready(None),
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.input.size_hint()
    }
}

#[cfg(test)]
mod test {
    use std::iter::repeat_with;

    use futures::stream::{iter as stream_iter, Stream, StreamExt, TryStreamExt};

    use crate::{
        error::Error,
        ff::Fp31,
        helpers::Direction,
        protocol::{basics::validate::ReplicatedValidator, context::Context, RecordId},
        rand::{thread_rng, Rng},
        secret_sharing::{
            replicated::{
                semi_honest::AdditiveShare as SemiHonestReplicated, ReplicatedSecretSharing,
            },
            SharedValue,
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    fn assert_stream<S: Stream<Item = Result<T, Error>>, T>(s: S) -> S {
        s
    }

    /// Successfully validate some shares.
    #[tokio::test]
    pub async fn simple() {
        let mut rng = thread_rng();
        let world = TestWorld::default();

        let input = repeat_with(|| rng.gen::<Fp31>())
            .take(10)
            .collect::<Vec<_>>();
        let result = world
            .semi_honest(input.into_iter(), |ctx, shares| async move {
                let ctx = ctx.set_total_records(shares.len());
                let s = stream_iter(shares).map(|x| Ok(x));
                let vs = ReplicatedValidator::new(ctx.narrow("validate"), s);
                let sum = assert_stream(vs)
                    .try_fold(Fp31::ZERO, |sum, value| async move {
                        Ok(sum + value.left() - value.right())
                    })
                    .await?;
                // This value should sum to zero now, so replicate the value.
                // (We don't care here that this reveals our share to other helpers, it's just a test.)
                ctx.send_channel(ctx.role().peer(Direction::Right))
                    .send(RecordId::FIRST, sum)
                    .await?;
                let left = ctx
                    .recv_channel(ctx.role().peer(Direction::Left))
                    .receive(RecordId::FIRST)
                    .await?;
                Ok(SemiHonestReplicated::new(left, sum))
            })
            .await
            .map(Result::<_, Error>::unwrap)
            .reconstruct();

        assert_eq!(Fp31::ZERO, result);
    }
}
