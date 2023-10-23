use std::ops::Add;

use futures::future;
use ipa_macros::Step;
use rand::{distributions::Standard, prelude::Distribution, seq::SliceRandom, Rng};

use super::super::{
    basics::apply_permutation::apply as apply_permutation, context::Context, RecordId,
};
use crate::{
    error::Error,
    helpers::{Direction, Message, ReceivingEnd, Role},
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        SharedValue,
    },
};

#[derive(Step)]
pub(crate) enum OPRFShuffleStep {
    GenerateAHat,
    GenerateBHat,
    GeneratePi,
    GenerateZ,
    TransferCHat,
    TransferX2,
    TransferY1,
}

/// # Errors
/// Will propagate errors from transport and a few typecasts
pub async fn shuffle<C, I, S>(ctx: C, batch_size: u32, shares: I) -> Result<(Vec<S>, Vec<S>), Error>
where
    C: Context,
    I: IntoIterator<Item = AdditiveShare<S>>,
    S: SharedValue + Add<Output = S> + Message,
    for<'b> &'b S: Add<S, Output = S>,
    for<'b> &'b S: Add<&'b S, Output = S>,
    Standard: Distribution<S>,
{
    // 1. Generate permutations
    let pis = generate_permutations_with_peers(batch_size, &ctx);

    // 2. Generate random tables used by all helpers
    let ctx_z = ctx.narrow(&OPRFShuffleStep::GenerateZ);
    let zs = generate_random_tables_with_peers(batch_size, &ctx_z);

    match ctx.role() {
        Role::H1 => run_h1(&ctx, batch_size, shares, pis, zs).await,
        Role::H2 => run_h2(&ctx, batch_size, shares, pis, zs).await,
        Role::H3 => run_h3(&ctx, batch_size, pis, zs).await,
    }
}

async fn run_h1<C, I, S, Zl, Zr>(
    ctx: &C,
    batch_size: u32,
    shares: I,
    (pi_31, pi_12): (Vec<u32>, Vec<u32>),
    (z_31, z_12): (Zl, Zr),
) -> Result<(Vec<S>, Vec<S>), Error>
where
    C: Context,
    I: IntoIterator<Item = AdditiveShare<S>>,
    S: SharedValue + Add<Output = S> + Message,
    Zl: IntoIterator<Item = S>,
    Zr: IntoIterator<Item = S>,
    for<'a> &'a S: Add<Output = S>,
    Standard: Distribution<S>,
{
    // 1. Generate helper-specific random tables
    let ctx_a_hat = ctx.narrow(&OPRFShuffleStep::GenerateAHat);
    let a_hat: Vec<_> =
        generate_random_table_solo(batch_size, &ctx_a_hat, Direction::Left).collect();

    let ctx_b_hat = ctx.narrow(&OPRFShuffleStep::GenerateBHat);
    let b_hat: Vec<_> =
        generate_random_table_solo(batch_size, &ctx_b_hat, Direction::Right).collect();

    // 2. Run computations
    let a_add_b_iter = shares
        .into_iter()
        .map(|s: AdditiveShare<S>| s.left().add(s.right()));
    let mut x_1: Vec<S> = add_single_shares(a_add_b_iter, z_12).collect();
    apply_permutation(&pi_12, &mut x_1);

    let mut x_2: Vec<S> = add_single_shares(x_1, z_31).collect();
    apply_permutation(&pi_31, &mut x_2);

    send_to_peer(ctx, &OPRFShuffleStep::TransferX2, Direction::Right, x_2).await?;

    Ok((a_hat, b_hat))
}

async fn run_h2<C, I, S, Zl, Zr>(
    ctx: &C,
    batch_size: u32,
    shares: I,
    (pi_12, pi_23): (Vec<u32>, Vec<u32>),
    (z_12, z_23): (Zl, Zr),
) -> Result<(Vec<S>, Vec<S>), Error>
where
    C: Context,
    I: IntoIterator<Item = AdditiveShare<S>>,
    S: SharedValue + Add<Output = S> + Message,
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
    apply_permutation(&pi_12, &mut y_1);

    let ((), x_2): ((), Vec<S>) = future::try_join(
        send_to_peer(ctx, &OPRFShuffleStep::TransferY1, Direction::Right, y_1),
        receive_from_peer(
            ctx,
            &OPRFShuffleStep::TransferX2,
            Direction::Left,
            batch_size,
        ),
    )
    .await?;

    let mut x_3: Vec<S> = add_single_shares(x_2.iter(), z_23).collect();
    apply_permutation(&pi_23, &mut x_3);

    let c_hat_1: Vec<S> = add_single_shares(x_3.iter(), b_hat.iter()).collect();
    let ((), c_hat_2) = future::try_join(
        send_to_peer(
            ctx,
            &OPRFShuffleStep::TransferCHat,
            Direction::Right,
            c_hat_1.clone(),
        ),
        receive_from_peer(
            ctx,
            &OPRFShuffleStep::TransferCHat,
            Direction::Right,
            batch_size,
        ),
    )
    .await?;

    let c_hat = add_single_shares(c_hat_1.iter(), c_hat_2.iter()).collect();
    Ok((b_hat, c_hat))
}

async fn run_h3<C, S, Zl, Zr>(
    ctx: &C,
    batch_size: u32,
    (pi_23, pi_31): (Vec<u32>, Vec<u32>),
    (z_23, z_31): (Zl, Zr),
) -> Result<(Vec<S>, Vec<S>), Error>
where
    C: Context,
    S: SharedValue + Add<Output = S> + Message,
    Zl: IntoIterator<Item = S>,
    Zr: IntoIterator<Item = S>,
    S: Clone + Add<Output = S> + Message,
    // for<'a> &'a S: Add<S, Output = S>,
    for<'a> &'a S: Add<&'a S, Output = S>,
    Standard: Distribution<S>,
{
    // 1. Generate helper-specific random tables
    let ctx_a_hat = ctx.narrow(&OPRFShuffleStep::GenerateAHat);
    let a_hat: Vec<S> =
        generate_random_table_solo(batch_size, &ctx_a_hat, Direction::Right).collect();

    // 2. Run computations
    let y_1: Vec<S> = receive_from_peer(
        ctx,
        &OPRFShuffleStep::TransferY1,
        Direction::Left,
        batch_size,
    )
    .await?;

    let mut y_2: Vec<S> = add_single_shares(y_1, z_31).collect();
    apply_permutation(&pi_31, &mut y_2);

    let mut y_3: Vec<S> = add_single_shares(y_2, z_23).collect();
    apply_permutation(&pi_23, &mut y_3);

    let c_hat_2: Vec<S> = add_single_shares(y_3.iter(), a_hat.iter()).collect();
    let ((), c_hat_1): ((), Vec<S>) = future::try_join(
        send_to_peer(
            ctx,
            &OPRFShuffleStep::TransferCHat,
            Direction::Left,
            c_hat_2.clone(),
        ),
        receive_from_peer(
            ctx,
            &OPRFShuffleStep::TransferCHat,
            Direction::Left,
            batch_size,
        ),
    )
    .await?;

    let c_hat = add_single_shares(c_hat_1, c_hat_2).collect();
    Ok((c_hat, a_hat))
}

fn add_single_shares<A, B, S, L, R>(l: L, r: R) -> impl Iterator<Item = S>
where
    A: Add<B, Output = S>,
    L: IntoIterator<Item = A>,
    R: IntoIterator<Item = B>,
{
    l.into_iter().zip(r).map(|(a, b)| a + b)
}
// --------------------------------------------------------------------------- //

fn generate_random_tables_with_peers<'a, C, S>(
    batch_size: u32,
    narrow_ctx: &'a C,
) -> (impl Iterator<Item = S> + 'a, impl Iterator<Item = S> + 'a)
where
    C: Context,
    Standard: Distribution<S>,
    S: 'a,
{
    let (rng_l, rng_r) = narrow_ctx.prss_rng();
    let with_left = rng_l.sample_iter(Standard).take(batch_size as usize);
    let with_right = rng_r.sample_iter(Standard).take(batch_size as usize);
    (with_left, with_right)
}

fn generate_random_table_solo<'a, C, S>(
    batch_size: u32,
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

    rng.sample_iter(Standard).take(batch_size as usize)
}

// ---------------------------- helper communication ------------------------------------ //

async fn send_to_peer<C, S, I>(
    ctx: &C,
    step: &OPRFShuffleStep,
    direction: Direction,
    items: I,
) -> Result<(), Error>
where
    C: Context,
    I: IntoIterator<Item = S>,
    S: Message,
{
    let role = ctx.role().peer(direction);
    let send_channel = ctx.narrow(step).send_channel(role);
    for (record_id, row) in items.into_iter().enumerate() {
        send_channel.send(RecordId::from(record_id), row).await?;
    }
    Ok(())
}

async fn receive_from_peer<C, S>(
    ctx: &C,
    step: &OPRFShuffleStep,
    direction: Direction,
    batch_size: u32,
) -> Result<Vec<S>, Error>
where
    C: Context,
    S: Message,
{
    let role = ctx.role().peer(direction);
    let receive_channel: ReceivingEnd<S> = ctx.narrow(step).recv_channel(role);

    let mut output: Vec<S> = Vec::with_capacity(batch_size as usize);
    for record_id in 0..batch_size {
        let msg = receive_channel.receive(RecordId::from(record_id)).await?;
        output.push(msg);
    }

    Ok(output)
}

// ------------------ Pseudorandom permutations functions -------------------- //

fn generate_permutations_with_peers<C: Context>(batch_size: u32, ctx: &C) -> (Vec<u32>, Vec<u32>) {
    let narrow_context = ctx.narrow(&OPRFShuffleStep::GeneratePi);
    let mut rng = narrow_context.prss_rng();

    let with_left = generate_pseudorandom_permutation(batch_size, &mut rng.0);
    let with_right = generate_pseudorandom_permutation(batch_size, &mut rng.1);
    (with_left, with_right)
}

fn generate_pseudorandom_permutation<R: Rng>(batch_size: u32, rng: &mut R) -> Vec<u32> {
    let mut permutation = (0..batch_size).collect::<Vec<_>>();
    permutation.shuffle(rng);
    permutation
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
    use std::ops::Add;

    use crate::secret_sharing::replicated::semi_honest::AdditiveShare;
    use crate::secret_sharing::replicated::ReplicatedSecretSharing;
    use crate::test_executor::run;
    use crate::{
        ff::{Field, Gf40Bit},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    use super::shuffle;

    pub type MatchKey = Gf40Bit;

    impl Add<&MatchKey> for &MatchKey {
        type Output = MatchKey;

        fn add(self, rhs: &MatchKey) -> Self::Output {
            Add::add(*self, *rhs)
        }
    }

    impl Add<MatchKey> for &MatchKey {
        type Output = MatchKey;

        fn add(self, rhs: MatchKey) -> Self::Output {
            Add::add(*self, rhs)
        }
    }

    #[test]
    fn added_random_tables_cancel_out() {
        run(|| async {
            let records = vec![MatchKey::truncate_from(12345 as u128) as MatchKey];
            let expected = records[0].clone();

            let world = TestWorld::default();

            let result = world
                .semi_honest(records.into_iter(), |ctx, shares| async move {
                    shuffle(ctx, 1, shares).await.unwrap()
                })
                .await;

            let result = result
                .into_iter()
                .map(|(l, r)| {
                    l.into_iter()
                        .zip(r)
                        .map(|(li, ri)| AdditiveShare::new(li, ri))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            let result: [Vec<_>; 3] = result.try_into().unwrap();
            let actual = result.reconstruct()[0];
            assert_eq!(actual, expected);
        });
    }
}
