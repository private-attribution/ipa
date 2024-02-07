#![allow(dead_code)] // Not wired in yet.

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

/// The finalizing state for the validator.
struct ReplicatedValidatorFinalization<'a> {
    f: Pin<Box<(dyn Future<Output = Result<(), Error>> + Send + 'a)>>,
}

impl<'a> ReplicatedValidatorFinalization<'a> {
    fn new<C: Context + 'a>(active: ReplicatedValidatorActive<'a, C>) -> Self {
        let ReplicatedValidatorActive {
            ctx,
            left_hash,
            right_hash,
            ..
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
                Err(Error::InconsistentShares)
            }
        }));
        Self { f }
    }

    fn poll(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        self.f.poll_unpin(cx)
    }
}

/// The active state for the validator.
struct ReplicatedValidatorActive<'a, C: 'a> {
    ctx: C,
    left_hash: Sha256,
    right_hash: Sha256,
    _marker: PhantomData<&'a ()>,
}

impl<'a, C: Context + 'a> ReplicatedValidatorActive<'a, C> {
    fn new(ctx: C) -> Self {
        Self {
            ctx,
            left_hash: HashFunction::new(),
            right_hash: HashFunction::new(),
            _marker: PhantomData,
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

    fn finalize(self) -> ReplicatedValidatorFinalization<'a> {
        ReplicatedValidatorFinalization::new(self)
    }
}

enum ReplicatedValidatorState<'a, C: 'a> {
    /// While the validator is waiting, it holds a context reference.
    Pending(Option<Box<ReplicatedValidatorActive<'a, C>>>),
    /// After the validator has taken all of its inputs, it holds a future.
    Finalizing(ReplicatedValidatorFinalization<'a>),
}

impl<'a, C: Context + 'a> ReplicatedValidatorState<'a, C> {
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

/// A `ReplicatedValidator` takes a stream of replicated shares of anything
/// and produces a stream of the same values, without modifying them.
/// The only thing it does is check that the values are consistent across
/// all three helpers using the provided context.
/// To do this, it sends a single message.
///
/// If validation passes, the stream is completely transparent.
/// If validation fails, the stream will error before it closes.
#[pin_project]
struct ReplicatedValidator<'a, C: 'a, T: Stream, S, V> {
    #[pin]
    input: Fuse<T>,
    state: ReplicatedValidatorState<'a, C>,
    _marker: PhantomData<(S, V)>,
}

impl<'a, C: Context + 'a, T: Stream, S, V> ReplicatedValidator<'a, C, T, S, V> {
    pub fn new(ctx: &C, s: T) -> Self {
        Self {
            input: s.fuse(),
            state: ReplicatedValidatorState::Pending(Some(Box::new(
                ReplicatedValidatorActive::new(ctx.set_total_records(1)),
            ))),
            _marker: PhantomData,
        }
    }
}

impl<'a, C, T, S, V> Stream for ReplicatedValidator<'a, C, T, S, V>
where
    C: Context + 'a,
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

#[cfg(all(test, unit_test))]
mod test {
    use std::iter::repeat_with;

    use futures::stream::{iter as stream_iter, Stream, StreamExt, TryStreamExt};

    use crate::{
        error::Error,
        ff::{Field, Fp31},
        helpers::{Direction, Role},
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
                let s = stream_iter(shares).map(Ok);
                let vs = ReplicatedValidator::new(&ctx.narrow("validate"), s);
                let sum = assert_stream(vs)
                    .try_fold(Fp31::ZERO, |sum, value| async move {
                        Ok(sum + value.left() - value.right())
                    })
                    .await?;
                let ctx = ctx.set_total_records(1);
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

    #[tokio::test]
    pub async fn inconsistent() {
        let mut rng = thread_rng();
        let world = TestWorld::default();

        let damage = |role| {
            let mut tweak = role == Role::H3;
            move |v: SemiHonestReplicated<Fp31>| -> SemiHonestReplicated<Fp31> {
                if tweak {
                    tweak = false;
                    SemiHonestReplicated::new(v.left(), v.right() + Fp31::ONE)
                } else {
                    v
                }
            }
        };

        let input = repeat_with(|| rng.gen::<Fp31>())
            .take(10)
            .collect::<Vec<_>>();
        let result = world
            .semi_honest(input.into_iter(), |ctx, shares| async move {
                let s = stream_iter(shares).map(damage(ctx.role())).map(Ok);
                let vs = ReplicatedValidator::new(&ctx.narrow("validate"), s);
                let sum = assert_stream(vs)
                    .try_fold(Fp31::ZERO, |sum, value| async move {
                        Ok(sum + value.left() - value.right())
                    })
                    .await?;
                Ok(sum) // This will be not be reached by 2/3 helpers.
            })
            .await;

        // With just one error having been introduced, two of three helpers will error out.
        assert!(matches!(
            result[0].as_ref().unwrap_err(),
            Error::InconsistentShares
        ));
        assert!(result[1].is_ok());
        assert!(matches!(
            result[2].as_ref().unwrap_err(),
            Error::InconsistentShares
        ));
    }
}
