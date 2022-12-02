use std::iter::{repeat, zip};

use crate::secret_sharing::SecretSharing;
use crate::{
    error::Error,
    ff::Field,
    helpers::{Direction, Role},
    protocol::{context::Context, RecordId},
};
use async_trait::async_trait;
use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;

use crate::protocol::sort::shuffle::{shuffle_for_helper, ShuffleOrUnshuffle};
use crate::protocol::sort::{
    apply::{apply, apply_inv},
    ShuffleStep::{self, Step1, Step2, Step3},
};

#[async_trait]
pub trait Resharable: Sized {
    async fn reshare<F, C, S>(
        &self,
        ctx: C,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self, Error>
    where
        F: Field,
        C: Context<F, Share = S> + Send,
        S: SecretSharing<F>;
}

async fn reshare<F, C, S, T>(input: &[T], ctx: C, to_helper: Role) -> Result<Vec<T>, Error>
where
    C: Context<F, Share = S> + Send,
    F: Field,
    S: SecretSharing<F>,
    T: Resharable,
{
    let reshares = zip(repeat(ctx), input)
        .enumerate()
        .map(|(index, (ctx, input))| async move {
            input.reshare(ctx, RecordId::from(index), to_helper).await
        });
    try_join_all(reshares).await
}

/// `shuffle_once` is called for the helpers
/// i)   2 helpers receive permutation pair and choose the permutation to be applied
/// ii)  2 helpers apply the permutation to their shares
/// iii) reshare to `to_helper`
async fn shuffle_once<F, S, C, I>(
    mut input: Vec<I>,
    random_permutations: (&[u32], &[u32]),
    shuffle_or_unshuffle: ShuffleOrUnshuffle,
    ctx: &C,
    which_step: ShuffleStep,
) -> Result<Vec<I>, Error>
where
    C: Context<F, Share = S> + Send,
    F: Field,
    I: Resharable,
    S: SecretSharing<F>,
{
    let to_helper = shuffle_for_helper(which_step);
    let ctx = ctx.narrow(&which_step);

    if to_helper != ctx.role() {
        let permutation_to_apply = if to_helper.peer(Direction::Left) == ctx.role() {
            random_permutations.0
        } else {
            random_permutations.1
        };

        match shuffle_or_unshuffle {
            ShuffleOrUnshuffle::Shuffle => apply_inv(permutation_to_apply, &mut input),
            ShuffleOrUnshuffle::Unshuffle => apply(permutation_to_apply, &mut input),
        }
    }
    reshare(&input, ctx, to_helper).await
}

#[embed_doc_image("shuffle", "images/sort/shuffle.png")]
/// Shuffle calls `shuffle_once` three times with 2 helpers shuffling the shares each time.
/// Order of calling `shuffle_once` is shuffle with (H2, H3), (H3, H1) and (H1, H2).
/// Each shuffle requires communication between helpers to perform reshare.
/// Infrastructure has a pre-requisite to distinguish each communication step uniquely.
/// For this, we have three shuffle steps one per `shuffle_once` i.e. Step1, Step2 and Step3.
/// The Shuffle object receives a step function and appends a `ShuffleStep` to form a concrete step
/// ![Shuffle steps][shuffle]
pub async fn shuffle_shares<C, F, I, S>(
    input: Vec<I>,
    random_permutations: (&[u32], &[u32]),
    ctx: C,
) -> Result<Vec<I>, Error>
where
    C: Context<F, Share = S> + Send,
    F: Field,
    I: Resharable,
    S: SecretSharing<F>,
{
    let input = shuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Step1,
    )
    .await?;
    let input = shuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Step2,
    )
    .await?;
    shuffle_once(
        input,
        random_permutations,
        ShuffleOrUnshuffle::Shuffle,
        &ctx,
        Step3,
    )
    .await
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {

    mod semi_honest {
        use crate::rand::{thread_rng, Rng};

        use crate::ff::Fp31;
        use crate::protocol::attribution::accumulate_credit::tests::AttributionTestInput;
        use crate::protocol::context::Context;
        use crate::protocol::sort::apply_sort::shuffle::shuffle_shares;
        use crate::protocol::sort::shuffle::get_two_of_three_random_permutations;
        use crate::protocol::QueryId;
        use crate::test_fixture::{Reconstruct, Runner, TestWorld};
        use std::collections::HashSet;

        #[tokio::test]
        async fn shuffle_attribution_input_row() {
            const BATCHSIZE: u8 = 25;
            let world = TestWorld::new(QueryId);
            let mut rng = thread_rng();

            let mut input: Vec<AttributionTestInput<Fp31>> = Vec::with_capacity(BATCHSIZE.into());
            input.resize_with(BATCHSIZE.into(), || {
                AttributionTestInput([(); 4].map(|_| rng.gen::<Fp31>()))
            });
            let hashed_input: HashSet<[u8; 4]> = input.iter().map(Into::into).collect();

            let result = world
                .semi_honest(input.clone(), |ctx, m_shares| async move {
                    let perms =
                        get_two_of_three_random_permutations(BATCHSIZE.into(), ctx.prss_rng());
                    shuffle_shares(
                        m_shares,
                        (perms.0.as_slice(), perms.1.as_slice()),
                        ctx.clone(),
                    )
                    .await
                    .unwrap()
                })
                .await;

            let mut hashed_output_secret = HashSet::new();
            let mut output_secret = Vec::new();
            for val in result.reconstruct() {
                output_secret.push(val.clone());
                hashed_output_secret.insert(val.into());
            }

            // Secrets should be shuffled
            assert_ne!(output_secret, input);

            // Shuffled output should have same inputs
            assert_eq!(hashed_output_secret, hashed_input);
        }
    }
}
