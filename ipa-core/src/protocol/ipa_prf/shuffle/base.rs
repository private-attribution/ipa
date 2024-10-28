use std::{
    num::NonZeroUsize,
    ops::{Add, AddAssign},
};

use futures::future;
use rand::{distributions::Standard, prelude::Distribution, seq::SliceRandom, Rng};

use crate::{
    error::Error,
    helpers::{Direction, MpcReceivingEnd, Role, TotalRecords},
    protocol::{
        context::Context,
        ipa_prf::shuffle::{step::OPRFShuffleStep, IntermediateShuffleMessages},
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        SharedValue,
    },
};

/// Internal entry point to non-sharded shuffle protocol, excluding validation of
/// intermediates for malicious security. Protocols should use `trait Shuffle`.
///
/// # Errors
/// Will propagate errors from transport and a few typecasts
pub(super) async fn shuffle_protocol<C, I, S>(
    ctx: C,
    shares: I,
) -> Result<(Vec<AdditiveShare<S>>, IntermediateShuffleMessages<S>), Error>
where
    C: Context,
    I: IntoIterator<Item = AdditiveShare<S>>,
    I::IntoIter: ExactSizeIterator,
    S: SharedValue + Add<Output = S>,
    for<'a> &'a S: Add<S, Output = S>,
    for<'a> &'a S: Add<&'a S, Output = S>,
    Standard: Distribution<S>,
{
    // TODO: this code works with iterators and that costs it an extra allocation at the end.
    // This protocol can take a mutable iterator and replace items in the input.
    let shares = shares.into_iter();
    let Some(shares_len) = NonZeroUsize::new(shares.len()) else {
        return Ok((vec![], IntermediateShuffleMessages::empty(&ctx)));
    };
    let ctx_z = ctx.narrow(&OPRFShuffleStep::GenerateZ);
    let zs = generate_random_tables_with_peers(shares_len, &ctx_z);

    match ctx.role() {
        Role::H1 => Box::pin(run_h1(&ctx, shares_len, shares, zs)).await,
        Role::H2 => Box::pin(run_h2(&ctx, shares_len, shares, zs)).await,
        Role::H3 => Box::pin(run_h3(&ctx, shares_len, zs)).await,
    }
}

async fn run_h1<C, I, S, Zl, Zr>(
    ctx: &C,
    batch_size: NonZeroUsize,
    shares: I,
    (z_31, z_12): (Zl, Zr),
) -> Result<(Vec<AdditiveShare<S>>, IntermediateShuffleMessages<S>), Error>
where
    C: Context,
    I: IntoIterator<Item = AdditiveShare<S>>,
    S: SharedValue + Add<Output = S>,
    Zl: IntoIterator<Item = S>,
    Zr: IntoIterator<Item = S>,
    for<'a> &'a S: Add<Output = S>,
    Standard: Distribution<S>,
{
    // 1. Generate helper-specific random tables
    let ctx_a_hat = ctx.narrow(&OPRFShuffleStep::GenerateAHat);
    let a_hat = generate_random_table_solo(batch_size, &ctx_a_hat, Direction::Left);

    let ctx_b_hat = ctx.narrow(&OPRFShuffleStep::GenerateBHat);
    let b_hat = generate_random_table_solo(batch_size, &ctx_b_hat, Direction::Right);

    // 2. Run computations
    let a_add_b_iter = shares
        .into_iter()
        .map(|s: AdditiveShare<S>| s.left().add(s.right()));
    let mut x_1: Vec<S> = add_single_shares(a_add_b_iter, z_12).collect();

    let ctx_perm = ctx.narrow(&OPRFShuffleStep::ApplyPermutations);
    let (mut rng_perm_l, mut rng_perm_r) = ctx_perm.prss_rng();
    x_1.shuffle(&mut rng_perm_r);

    // need to output x_1
    // call to clone causes allocation
    // ideally in the semi honest setting, we would not clone
    let mut x_2 = x_1.clone();
    add_single_shares_in_place(&mut x_2, z_31);
    x_2.shuffle(&mut rng_perm_l);
    send_to_peer(&x_2, ctx, &OPRFShuffleStep::TransferX2, Direction::Right).await?;

    let res = combine_single_shares(a_hat, b_hat).collect::<Vec<_>>();
    // we only need to store x_1 in IntermediateShuffleMessage
    Ok((res, IntermediateShuffleMessages::H1 { x1: x_1 }))
}

async fn run_h2<C, I, S, Zl, Zr>(
    ctx: &C,
    batch_size: NonZeroUsize,
    shares: I,
    (z_12, z_23): (Zl, Zr),
) -> Result<(Vec<AdditiveShare<S>>, IntermediateShuffleMessages<S>), Error>
where
    C: Context,
    I: IntoIterator<Item = AdditiveShare<S>>,
    S: SharedValue + Add<Output = S>,
    Zl: IntoIterator<Item = S>,
    Zr: IntoIterator<Item = S>,
    for<'a> &'a S: Add<S, Output = S>,
    for<'a> &'a S: Add<&'a S, Output = S>,
    Standard: Distribution<S>,
{
    // 1. Generate helper-specific random tables
    let ctx_b_hat = ctx.narrow(&OPRFShuffleStep::GenerateBHat);
    let b_hat: Vec<S> =
        generate_random_table_solo(batch_size, &ctx_b_hat, Direction::Left).collect();

    // 2. Run computations
    let c = shares.into_iter().map(|s| s.right());
    let mut y_1: Vec<S> = add_single_shares(c, z_12).collect();

    let ctx_perm = ctx.narrow(&OPRFShuffleStep::ApplyPermutations);
    let (mut rng_perm_l, mut rng_perm_r) = ctx_perm.prss_rng();
    y_1.shuffle(&mut rng_perm_l);

    let mut x_2: Vec<S> = Vec::with_capacity(batch_size.get());
    future::try_join(
        send_to_peer(&y_1, ctx, &OPRFShuffleStep::TransferY1, Direction::Right),
        receive_from_peer_into(
            &mut x_2,
            batch_size,
            ctx,
            &OPRFShuffleStep::TransferX2,
            Direction::Left,
        ),
    )
    .await?;

    // we need to output x_2
    // call to clone causes allocation
    // ideally in the semi honest setting, we would not clone
    let mut x_3 = x_2.clone();
    add_single_shares_in_place(&mut x_3, z_23);
    x_3.shuffle(&mut rng_perm_r);

    let mut c_hat_1 = repurpose_allocation(y_1);
    c_hat_1.extend(add_single_shares(x_3.iter(), b_hat.iter()));

    let mut c_hat_2 = repurpose_allocation(x_3);
    future::try_join(
        send_to_peer(
            &c_hat_1,
            ctx,
            &OPRFShuffleStep::TransferCHat,
            Direction::Right,
        ),
        receive_from_peer_into(
            &mut c_hat_2,
            batch_size,
            ctx,
            &OPRFShuffleStep::TransferCHat,
            Direction::Right,
        ),
    )
    .await?;

    let c_hat = add_single_shares(c_hat_1.iter(), c_hat_2.iter());
    let res = combine_single_shares(b_hat, c_hat).collect::<Vec<_>>();
    // we only need to store x_2 in IntermediateShuffleMessage
    Ok((res, IntermediateShuffleMessages::H2 { x2: x_2 }))
}

async fn run_h3<C, S, Zl, Zr>(
    ctx: &C,
    batch_size: NonZeroUsize,
    (z_23, z_31): (Zl, Zr),
) -> Result<(Vec<AdditiveShare<S>>, IntermediateShuffleMessages<S>), Error>
where
    C: Context,
    S: SharedValue + Add<Output = S>,
    Zl: IntoIterator<Item = S>,
    Zr: IntoIterator<Item = S>,
    for<'a> &'a S: Add<&'a S, Output = S>,
    Standard: Distribution<S>,
{
    // 1. Generate helper-specific random tables
    let ctx_a_hat = ctx.narrow(&OPRFShuffleStep::GenerateAHat);
    let a_hat: Vec<S> =
        generate_random_table_solo(batch_size, &ctx_a_hat, Direction::Right).collect();

    // 2. Run computations
    let mut y_1 = Vec::<S>::with_capacity(batch_size.get());
    receive_from_peer_into(
        &mut y_1,
        batch_size,
        ctx,
        &OPRFShuffleStep::TransferY1,
        Direction::Left,
    )
    .await?;

    // need to output y_1
    // call to clone causes allocation
    // ideally in the semi honest setting, we would not clone
    let mut y_2 = y_1.clone();
    add_single_shares_in_place(&mut y_2, z_31);

    let ctx_perm = ctx.narrow(&OPRFShuffleStep::ApplyPermutations);
    let (mut rng_perm_l, mut rng_perm_r) = ctx_perm.prss_rng();
    y_2.shuffle(&mut rng_perm_r);

    // need to output y_2
    // call to clone causes allocation
    // ideally in the semi honest setting, we would not clone
    let mut y_3 = y_2.clone();
    add_single_shares_in_place(&mut y_3, z_23);
    y_3.shuffle(&mut rng_perm_l);

    let c_hat_2: Vec<S> = add_single_shares(y_3.iter(), a_hat.iter()).collect();
    let mut c_hat_1 = repurpose_allocation(y_3);
    future::try_join(
        send_to_peer(
            &c_hat_2,
            ctx,
            &OPRFShuffleStep::TransferCHat,
            Direction::Left,
        ),
        receive_from_peer_into(
            &mut c_hat_1,
            batch_size,
            ctx,
            &OPRFShuffleStep::TransferCHat,
            Direction::Left,
        ),
    )
    .await?;

    let c_hat = add_single_shares(c_hat_1, c_hat_2);
    let res = combine_single_shares(c_hat, a_hat).collect::<Vec<_>>();
    Ok((res, IntermediateShuffleMessages::H3 { y1: y_1, y2: y_2 }))
}

fn add_single_shares<A, B, S, L, R>(l: L, r: R) -> impl Iterator<Item = S>
where
    A: Add<B, Output = S>,
    L: IntoIterator<Item = A>,
    R: IntoIterator<Item = B>,
{
    l.into_iter().zip(r).map(|(a, b)| a + b)
}

fn add_single_shares_in_place<S, R>(items: &mut [S], r: R)
where
    S: AddAssign,
    R: IntoIterator<Item = S>,
{
    items
        .iter_mut()
        .zip(r)
        .for_each(|(item, rhs)| item.add_assign(rhs));
}

fn repurpose_allocation<S>(mut buf: Vec<S>) -> Vec<S> {
    buf.clear();
    buf
}

// --------------------------------------------------------------------------- //

fn combine_single_shares<S, Il, Ir>(l: Il, r: Ir) -> impl Iterator<Item = AdditiveShare<S>>
where
    S: SharedValue,
    Il: IntoIterator<Item = S>,
    Ir: IntoIterator<Item = S>,
{
    l.into_iter()
        .zip(r)
        .map(|(li, ri)| AdditiveShare::new(li, ri))
}

fn generate_random_tables_with_peers<'a, C, S>(
    batch_size: NonZeroUsize,
    narrow_ctx: &'a C,
) -> (impl Iterator<Item = S> + 'a, impl Iterator<Item = S> + 'a)
where
    C: Context,
    Standard: Distribution<S>,
    S: 'a,
{
    let (rng_l, rng_r) = narrow_ctx.prss_rng();
    let with_left = rng_l.sample_iter(Standard).take(batch_size.get());
    let with_right = rng_r.sample_iter(Standard).take(batch_size.get());
    (with_left, with_right)
}

fn generate_random_table_solo<'a, C, S>(
    batch_size: NonZeroUsize,
    narrow_ctx: &'a C,
    peer: Direction,
) -> impl Iterator<Item = S> + 'a
where
    C: Context,
    Standard: Distribution<S>,
    S: 'a,
{
    let rngs = narrow_ctx.prss_rng();
    let rng = match peer {
        Direction::Left => rngs.0,
        Direction::Right => rngs.1,
    };

    rng.sample_iter(Standard).take(batch_size.get())
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
    S: Copy + SharedValue,
{
    let role = ctx.role().peer(direction);
    let send_channel = ctx
        .narrow(step)
        .set_total_records(TotalRecords::specified(items.len())?)
        .send_channel(role);

    for (record_id, row) in items.iter().enumerate() {
        send_channel.send(RecordId::from(record_id), *row).await?;
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
    S: SharedValue,
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
        ff::{Gf40Bit, U128Conversions},
        protocol::ipa_prf::shuffle::base::test_helpers::{
            extract_shuffle_results, ExtractedShuffleResults,
        },
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig},
    };

    pub type MatchKey = Gf40Bit;

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

        actual.sort();

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
            // using Gf40Bit here since it implements cmp such that vec can later be sorted
            let mut records = (0..RECORD_AMOUNT)
                .map(|_| rng.gen())
                .collect::<Vec<Gf40Bit>>();

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
            records.sort();
            x1_xor_y1.sort();
            x2_xor_y2.sort();
            a_xor_b_xor_c.sort();

            assert_eq!(records, a_xor_b_xor_c);
            assert_eq!(records, x1_xor_y1);
            assert_eq!(records, x2_xor_y2);
        });
    }
}
