use std::{
    num::NonZeroUsize,
    ops::{Add, AddAssign},
};

use futures::future;
use rand::{distributions::Standard, prelude::Distribution, seq::SliceRandom, Rng};

use crate::{
    error::Error,
    helpers::{Direction, MpcReceivingEnd, Role, TotalRecords},
    protocol::{context::Context, ipa_prf::shuffle::step::OPRFShuffleStep, RecordId},
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        SharedValue,
    },
};

/// # Errors
/// Will propagate errors from transport and a few typecasts
pub async fn shuffle<C, I, S>(ctx: C, shares: I) -> Result<Vec<AdditiveShare<S>>, Error>
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
        return Ok(vec![]);
    };
    let ctx_z = ctx.narrow(&OPRFShuffleStep::GenerateZ);
    let zs = generate_random_tables_with_peers(shares_len, &ctx_z);

    match ctx.role() {
        Role::H1 => run_h1(&ctx, shares_len, shares, zs).await,
        Role::H2 => run_h2(&ctx, shares_len, shares, zs).await,
        Role::H3 => run_h3(&ctx, shares_len, zs).await,
    }
}

async fn run_h1<C, I, S, Zl, Zr>(
    ctx: &C,
    batch_size: NonZeroUsize,
    shares: I,
    (z_31, z_12): (Zl, Zr),
) -> Result<Vec<AdditiveShare<S>>, Error>
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

    let mut x_2 = x_1;
    add_single_shares_in_place(&mut x_2, z_31);
    x_2.shuffle(&mut rng_perm_l);
    send_to_peer(&x_2, ctx, &OPRFShuffleStep::TransferX2, Direction::Right).await?;

    let res = combine_single_shares(a_hat, b_hat).collect::<Vec<_>>();
    Ok(res)
}

async fn run_h2<C, I, S, Zl, Zr>(
    ctx: &C,
    batch_size: NonZeroUsize,
    shares: I,
    (z_12, z_23): (Zl, Zr),
) -> Result<Vec<AdditiveShare<S>>, Error>
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

    let mut x_3 = x_2;
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
    Ok(res)
}

async fn run_h3<C, S, Zl, Zr>(
    ctx: &C,
    batch_size: NonZeroUsize,
    (z_23, z_31): (Zl, Zr),
) -> Result<Vec<AdditiveShare<S>>, Error>
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

    let mut y_2 = y_1;
    add_single_shares_in_place(&mut y_2, z_31);

    let ctx_perm = ctx.narrow(&OPRFShuffleStep::ApplyPermutations);
    let (mut rng_perm_l, mut rng_perm_r) = ctx_perm.prss_rng();
    y_2.shuffle(&mut rng_perm_r);

    let mut y_3 = y_2;
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
    Ok(res)
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

#[cfg(all(test, unit_test))]
pub mod tests {
    use super::shuffle;
    use crate::{
        ff::{Gf40Bit, U128Conversions},
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
                shuffle(ctx, shares).await.unwrap()
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
}
