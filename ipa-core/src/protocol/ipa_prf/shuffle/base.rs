use std::{borrow::Borrow, num::NonZeroUsize, ops::Add};

use futures::future;
use rand::seq::SliceRandom;

use crate::{
    error::Error,
    helpers::{Direction, MpcReceivingEnd, Role, TotalRecords},
    protocol::{
        context::Context,
        ipa_prf::shuffle::{
            sharded::Shuffleable, step::OPRFShuffleStep, IntermediateShuffleMessages,
        },
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::Sendable,
};

/// Internal entry point to non-sharded shuffle protocol, excluding validation of
/// intermediates for malicious security. Protocols should use `trait Shuffle`.
///
/// # Errors
/// Will propagate errors from transport and a few typecasts
pub(super) async fn shuffle_protocol<C, S, I>(
    ctx: C,
    shares: I,
) -> Result<(Vec<S>, IntermediateShuffleMessages<S::Share>), Error>
where
    C: Context,
    S: Shuffleable,
    I: IntoIterator<Item = S>,
    I::IntoIter: ExactSizeIterator,
{
    // TODO: this code works with iterators and that costs it an extra allocation at the end.
    // This protocol can take a mutable iterator and replace items in the input.
    let shares = shares.into_iter();
    let Some(shares_len) = NonZeroUsize::new(shares.len()) else {
        return Ok((vec![], IntermediateShuffleMessages::empty(&ctx)));
    };
    let zs = generate_random_tables_with_peers::<_, S>(
        ctx.narrow(&OPRFShuffleStep::GenerateZ),
        shares_len,
    );

    match ctx.role() {
        Role::H1 => Box::pin(run_h1(&ctx, shares_len, shares, zs)).await,
        Role::H2 => Box::pin(run_h2(&ctx, shares_len, shares, zs)).await,
        Role::H3 => Box::pin(run_h3(&ctx, shares_len, zs)).await,
    }
}

async fn run_h1<C, S, I, Zl, Zr>(
    ctx: &C,
    batch_size: NonZeroUsize,
    shares: I,
    (z_31, z_12): (Zl, Zr),
) -> Result<(Vec<S>, IntermediateShuffleMessages<S::Share>), Error>
where
    C: Context,
    S: Shuffleable,
    I: IntoIterator<Item = S>,
    Zl: IntoIterator<Item = S::Share>,
    Zr: IntoIterator<Item = S::Share>,
{
    // 1. Generate helper-specific random tables
    let a_hat = generate_random_table_solo::<_, S>(
        ctx.narrow(&OPRFShuffleStep::GenerateAHat),
        Direction::Left,
        batch_size,
    );

    let b_hat = generate_random_table_solo::<_, S>(
        ctx.narrow(&OPRFShuffleStep::GenerateBHat),
        Direction::Right,
        batch_size,
    );

    // 2. Run computations
    let a_add_b_iter = shares.into_iter().map(|s: S| s.left().add(s.right()));
    let mut x_1 = add_single_shares::<S, _>(a_add_b_iter, z_12).collect::<Vec<_>>();

    let ctx_perm = ctx.narrow(&OPRFShuffleStep::ApplyPermutations);
    let (mut rng_perm_l, mut rng_perm_r) = ctx_perm.prss_rng();
    x_1.shuffle(&mut rng_perm_r);

    // Need to output x_1. Ideally in the semi honest setting, we would add to x_1 in
    // place instead of allocating for x_2.
    let mut x_2 = add_single_shares::<S, _>(x_1.iter().cloned(), z_31).collect::<Vec<_>>();
    x_2.shuffle(&mut rng_perm_l);
    send_to_peer(&x_2, ctx, &OPRFShuffleStep::TransferXY, Direction::Right).await?;

    let res = combine_single_shares::<S, _, _>(a_hat, b_hat).collect::<Vec<_>>();
    // we only need to store x_1 in IntermediateShuffleMessage
    Ok((res, IntermediateShuffleMessages::H1 { x1: x_1 }))
}

async fn run_h2<C, S, I, Zl, Zr>(
    ctx: &C,
    batch_size: NonZeroUsize,
    shares: I,
    (z_12, z_23): (Zl, Zr),
) -> Result<(Vec<S>, IntermediateShuffleMessages<S::Share>), Error>
where
    C: Context,
    S: Shuffleable,
    I: IntoIterator<Item = S>,
    Zl: IntoIterator<Item = S::Share>,
    Zr: IntoIterator<Item = S::Share>,
{
    // 1. Generate helper-specific random tables
    let b_hat = generate_random_table_solo::<_, S>(
        ctx.narrow(&OPRFShuffleStep::GenerateBHat),
        Direction::Left,
        batch_size,
    )
    .collect::<Vec<_>>();

    // 2. Run computations
    let c = shares.into_iter().map(|s| s.right());
    let mut y_1 = add_single_shares::<S, _>(c, z_12).collect::<Vec<_>>();

    let ctx_perm = ctx.narrow(&OPRFShuffleStep::ApplyPermutations);
    let (mut rng_perm_l, mut rng_perm_r) = ctx_perm.prss_rng();
    y_1.shuffle(&mut rng_perm_l);

    let mut x_2: Vec<S::Share> = Vec::with_capacity(batch_size.get());
    future::try_join(
        send_to_peer(&y_1, ctx, &OPRFShuffleStep::TransferXY, Direction::Right),
        receive_from_peer_into(
            &mut x_2,
            batch_size,
            ctx,
            &OPRFShuffleStep::TransferXY,
            Direction::Left,
        ),
    )
    .await?;

    // Need to output x_2. Ideally in the semi honest setting, we would add to x_2 in
    // place instead of allocating for x_3.
    let mut x_3 = add_single_shares::<S, _>(x_2.iter().cloned(), z_23).collect::<Vec<_>>();
    x_3.shuffle(&mut rng_perm_r);

    let c_hat_1 = add_single_shares_in_place::<S, _>(x_3, &b_hat);

    let mut c_hat_2 = repurpose_allocation(y_1);
    future::try_join(
        send_to_peer(&c_hat_1, ctx, &OPRFShuffleStep::TransferC, Direction::Right),
        receive_from_peer_into(
            &mut c_hat_2,
            batch_size,
            ctx,
            &OPRFShuffleStep::TransferC,
            Direction::Right,
        ),
    )
    .await?;

    let c_hat = add_single_shares::<S, _>(c_hat_1, &c_hat_2);
    let res = combine_single_shares(b_hat, c_hat).collect::<Vec<_>>();
    // we only need to store x_2 in IntermediateShuffleMessage
    Ok((res, IntermediateShuffleMessages::H2 { x2: x_2 }))
}

async fn run_h3<C, S, Zl, Zr>(
    ctx: &C,
    batch_size: NonZeroUsize,
    (z_23, z_31): (Zl, Zr),
) -> Result<(Vec<S>, IntermediateShuffleMessages<S::Share>), Error>
where
    C: Context,
    S: Shuffleable,
    Zl: IntoIterator<Item = S::Share>,
    Zr: IntoIterator<Item = S::Share>,
{
    // 1. Generate helper-specific random tables
    let a_hat = generate_random_table_solo::<_, S>(
        ctx.narrow(&OPRFShuffleStep::GenerateAHat),
        Direction::Right,
        batch_size,
    )
    .collect::<Vec<_>>();

    // 2. Run computations
    let mut y_1 = Vec::<S::Share>::with_capacity(batch_size.get());
    receive_from_peer_into(
        &mut y_1,
        batch_size,
        ctx,
        &OPRFShuffleStep::TransferXY,
        Direction::Left,
    )
    .await?;

    // Need to output y_1. Ideally in the semi honest setting, we would add to y_1 in
    // place instead of allocating for y_2.
    let mut y_2 = add_single_shares::<S, _>(y_1.iter().cloned(), z_31).collect::<Vec<_>>();

    let ctx_perm = ctx.narrow(&OPRFShuffleStep::ApplyPermutations);
    let (mut rng_perm_l, mut rng_perm_r) = ctx_perm.prss_rng();
    y_2.shuffle(&mut rng_perm_r);

    // Need to output y_2. Ideally in the semi honest setting, we would add to y_2 in
    // place instead of allocating for y_3.
    let mut y_3 = add_single_shares::<S, _>(y_2.iter().cloned(), z_23).collect::<Vec<_>>();
    y_3.shuffle(&mut rng_perm_l);

    let c_hat_2 = add_single_shares_in_place::<S, _>(y_3, &a_hat);

    let mut c_hat_1 = Vec::with_capacity(batch_size.get());
    future::try_join(
        send_to_peer(&c_hat_2, ctx, &OPRFShuffleStep::TransferC, Direction::Left),
        receive_from_peer_into(
            &mut c_hat_1,
            batch_size,
            ctx,
            &OPRFShuffleStep::TransferC,
            Direction::Left,
        ),
    )
    .await?;

    let c_hat = add_single_shares::<S, _>(c_hat_1, c_hat_2);
    let res = combine_single_shares(c_hat, a_hat).collect::<Vec<_>>();
    Ok((res, IntermediateShuffleMessages::H3 { y1: y_1, y2: y_2 }))
}

fn add_single_shares<S: Shuffleable, B: Borrow<S::Share>>(
    l: impl IntoIterator<Item = S::Share>,
    r: impl IntoIterator<Item = B>,
) -> impl Iterator<Item = S::Share> {
    l.into_iter().zip(r).map(|(a, b)| a + b.borrow())
}

fn add_single_shares_in_place<S, I>(mut l: Vec<S::Share>, r: I) -> Vec<S::Share>
where
    S: Shuffleable,
    I: IntoIterator,
    I::Item: Borrow<S::Share>,
{
    l.iter_mut()
        .zip(r)
        .for_each(|(item, rhs)| *item += rhs.borrow());

    l
}

fn repurpose_allocation<T>(mut buf: Vec<T>) -> Vec<T> {
    buf.clear();
    buf
}

// --------------------------------------------------------------------------- //

fn combine_single_shares<S, Il, Ir>(l: Il, r: Ir) -> impl Iterator<Item = S>
where
    S: Shuffleable,
    Il: IntoIterator<Item = S::Share>,
    Ir: IntoIterator<Item = S::Share>,
{
    l.into_iter()
        .zip(r)
        .map(|(li, ri)| Shuffleable::new(li, ri))
}

fn generate_random_tables_with_peers<'ctx, C, S>(
    ctx: C,
    batch_size: NonZeroUsize,
) -> (
    impl Iterator<Item = S::Share> + 'ctx,
    impl Iterator<Item = S::Share> + 'ctx,
)
where
    C: Context + 'ctx,
    S: Shuffleable,
{
    let ctx_left = ctx.clone();
    let ctx_right = ctx;
    let left = (0..batch_size.get()).map(move |i| {
        ctx_left
            .prss()
            .generate_one_side(RecordId::from(i), Direction::Left)
    });
    let right = (0..batch_size.get()).map(move |i| {
        ctx_right
            .prss()
            .generate_one_side(RecordId::from(i), Direction::Right)
    });
    (left, right)
}

fn generate_random_table_solo<'ctx, C, S>(
    ctx: C,
    direction: Direction,
    batch_size: NonZeroUsize,
) -> impl Iterator<Item = S::Share> + 'ctx
where
    C: Context + 'ctx,
    S: Shuffleable,
{
    (0..batch_size.get()).map(move |i| ctx.prss().generate_one_side(RecordId::from(i), direction))
}

// ---------------------------- helper communication ------------------------------------ //

async fn send_to_peer<C, S>(
    items: &[S],
    ctx: &C,
    step: &OPRFShuffleStep,
    direction: Direction,
) -> Result<(), Error>
where
    C: Context,
    S: Sendable,
{
    let role = ctx.role().peer(direction);
    let send_channel = ctx
        .narrow(step)
        .set_total_records(TotalRecords::specified(items.len())?)
        .send_channel::<S>(role);

    for (record_id, row) in items.iter().enumerate() {
        send_channel.send(RecordId::from(record_id), row).await?;
    }
    Ok(())
}

async fn receive_from_peer_into<C, S>(
    buf: &mut Vec<S>,
    batch_size: NonZeroUsize,
    ctx: &C,
    step: &OPRFShuffleStep,
    direction: Direction,
) -> Result<(), Error>
where
    C: Context,
    S: Sendable,
{
    let role = ctx.role().peer(direction);
    let receive_channel: MpcReceivingEnd<S> = ctx
        .narrow(step)
        .set_total_records(batch_size)
        .recv_channel(role);

    for record_id in 0..batch_size.get() {
        let msg = receive_channel.receive(RecordId::from(record_id)).await?;
        buf.push(msg);
    }
    Ok(())
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub(super) mod test_helpers {
    use std::iter::zip;

    use crate::{
        protocol::ipa_prf::shuffle::IntermediateShuffleMessages,
        secret_sharing::{
            replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
            SharedValue,
        },
    };

    fn check_replicated_shares<'a, S, I1, I2>(left_helper_shares: I1, right_helper_shares: I2)
    where
        S: SharedValue,
        I1: Iterator<Item = &'a AdditiveShare<S>>,
        I2: Iterator<Item = &'a AdditiveShare<S>>,
    {
        assert!(zip(left_helper_shares, right_helper_shares)
            .all(|(lhs, rhs)| lhs.right() == rhs.left()));
    }

    pub struct ExtractedShuffleResults<S> {
        pub x1_xor_y1: Vec<S>,
        pub x2_xor_y2: Vec<S>,
        pub a_xor_b_xor_c: Vec<S>,
    }

    impl<S> ExtractedShuffleResults<S> {
        pub fn empty() -> Self {
            ExtractedShuffleResults {
                x1_xor_y1: vec![],
                x2_xor_y2: vec![],
                a_xor_b_xor_c: vec![],
            }
        }
    }

    /// Extract the data returned from shuffle (the shuffled records and intermediate
    /// values) into a more usable form for verification. This routine is used for
    /// both the unsharded and sharded shuffles.
    pub fn extract_shuffle_results<S: SharedValue>(
        results: [(Vec<AdditiveShare<S>>, IntermediateShuffleMessages<S>); 3],
    ) -> ExtractedShuffleResults<S> {
        // check consistency
        // i.e. x_1 xor y_1 = x_2 xor y_2 = C xor A xor B
        let [(h1_shares, h1_messages), (h2_shares, h2_messages), (h3_shares, h3_messages)] =
            results;

        let IntermediateShuffleMessages::H1 { x1 } = h1_messages else {
            panic!("H1 returned shuffle messages for {:?}", h1_messages.role());
        };
        let IntermediateShuffleMessages::H2 { x2 } = h2_messages else {
            panic!("H2 returned shuffle messages for {:?}", h2_messages.role());
        };
        let IntermediateShuffleMessages::H3 { y1, y2 } = h3_messages else {
            panic!("H3 returned shuffle messages for {:?}", h3_messages.role());
        };

        check_replicated_shares(h1_shares.iter(), h2_shares.iter());
        check_replicated_shares(h2_shares.iter(), h3_shares.iter());
        check_replicated_shares(h3_shares.iter(), h1_shares.iter());

        let x1_xor_y1 = zip(x1, y1).map(|(x1, y1)| x1 + y1).collect();

        let x2_xor_y2 = zip(x2, y2).map(|(x2, y2)| x2 + y2).collect();

        let a_xor_b_xor_c = zip(&h1_shares, h3_shares)
            .map(|(h1_share, h3_share)| h1_share.left() + h1_share.right() + h3_share.left())
            .collect();

        ExtractedShuffleResults {
            x1_xor_y1,
            x2_xor_y2,
            a_xor_b_xor_c,
        }
    }
}

#[cfg(all(test, unit_test))]
pub(super) mod tests {
    use rand::{thread_rng, Rng};

    use super::shuffle_protocol;
    use crate::{
        ff::{boolean_array::BA64, U128Conversions},
        protocol::ipa_prf::shuffle::base::test_helpers::{
            extract_shuffle_results, ExtractedShuffleResults,
        },
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig},
    };

    pub type MatchKey = BA64;

    #[tokio::test]
    async fn shuffles_the_order() {
        let mut i: u128 = 0;
        let records = std::iter::from_fn(move || {
            i += 1;
            Some(MatchKey::truncate_from(i))
        })
        .take(100)
        .collect::<Vec<_>>();

        // Stable seed is used to get predictable shuffle results.
        let mut actual = TestWorld::new_with(TestWorldConfig::default().with_seed(123))
            .semi_honest(records.clone().into_iter(), |ctx, shares| async move {
                shuffle_protocol(ctx, shares).await.unwrap().0
            })
            .await
            .reconstruct();

        assert_ne!(
            actual, records,
            "Shuffle should produce a different order of items"
        );

        actual.sort_by_key(U128Conversions::as_u128);

        assert_eq!(
            actual, records,
            "Shuffle should not change the items in the set"
        );
    }

    #[test]
    fn check_intermediate_messages() {
        const RECORD_AMOUNT: usize = 100;
        run(|| async {
            let world = TestWorld::default();
            let mut rng = thread_rng();
            let mut records = (0..RECORD_AMOUNT).map(|_| rng.gen()).collect::<Vec<BA64>>();

            let results = world
                .semi_honest(records.clone().into_iter(), |ctx, records| async move {
                    shuffle_protocol(ctx, records).await.unwrap()
                })
                .await;

            let ExtractedShuffleResults {
                mut x1_xor_y1,
                mut x2_xor_y2,
                mut a_xor_b_xor_c,
            } = extract_shuffle_results(results);

            // unshuffle by sorting
            records.sort_by_key(U128Conversions::as_u128);
            x1_xor_y1.sort_by_key(U128Conversions::as_u128);
            x2_xor_y2.sort_by_key(U128Conversions::as_u128);
            a_xor_b_xor_c.sort_by_key(U128Conversions::as_u128);

            assert_eq!(records, a_xor_b_xor_c);
            assert_eq!(records, x1_xor_y1);
            assert_eq!(records, x2_xor_y2);
        });
    }
}
