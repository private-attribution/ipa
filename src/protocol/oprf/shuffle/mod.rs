pub mod share;

use std::ops::Add;

use futures::future;
use ipa_macros::Step;
use rand::{distributions::Standard, seq::SliceRandom, Rng};

use self::share::{ShuffleShare, ShuffleShareBK, ShuffleShareF, ShuffleShareMK};
use super::super::{
    context::Context, ipa::IPAInputRow, sort::apply::apply as apply_permutation, RecordId,
};
use crate::{
    error::Error,
    helpers::{query::oprf_shuffle::QueryConfig, Direction, ReceivingEnd, Role},
};

pub type ShuffleInputRow = IPAInputRow<ShuffleShareF, ShuffleShareMK, ShuffleShareBK>;

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
pub async fn shuffle<C: Context>(
    ctx: C,
    input_rows: &[ShuffleInputRow],
    _config: QueryConfig,
) -> Result<Vec<ShuffleInputRow>, Error> {
    let batch_size = u32::try_from(input_rows.len()).map_err(|_e| {
        Error::FieldValueTruncation(format!(
            "Cannot truncate the number of input rows {} to u32",
            input_rows.len(),
        ))
    })?;

    let shares = (
        split_shares(input_rows, Direction::Left),
        split_shares(input_rows, Direction::Right),
    );

    // 1. Generate permutations
    let pis = generate_permutations_with_peers(batch_size, &ctx);

    // 2. Generate random tables used by all helpers
    let ctx_z = ctx.narrow(&OPRFShuffleStep::GenerateZ);
    let zs = generate_random_tables_with_peers(batch_size, &ctx_z);

    match ctx.role() {
        Role::H1 => run_h1(&ctx, batch_size, shares, pis, zs).await,
        Role::H2 => run_h2(&ctx, batch_size, shares, pis, zs).await,
        Role::H3 => run_h3(&ctx, batch_size, shares, pis, zs).await,
    }
}

async fn run_h1<C, Sl, Sr, Zl, Zr>(
    ctx: &C,
    batch_size: u32,
    (a, b): (Sl, Sr),
    (pi_31, pi_12): (Vec<u32>, Vec<u32>),
    (z_31, z_12): (Zl, Zr),
) -> Result<Vec<ShuffleInputRow>, Error>
where
    C: Context,
    Sl: IntoIterator<Item = ShuffleShare>,
    Sr: IntoIterator<Item = ShuffleShare>,
    Zl: IntoIterator<Item = ShuffleShare>,
    Zr: IntoIterator<Item = ShuffleShare>,
{
    // 1. Generate helper-specific random tables
    let ctx_a_hat = ctx.narrow(&OPRFShuffleStep::GenerateAHat);
    let a_hat: Vec<_> =
        generate_random_table_solo(batch_size, &ctx_a_hat, Direction::Left).collect();

    let ctx_b_hat = ctx.narrow(&OPRFShuffleStep::GenerateBHat);
    let b_hat: Vec<_> =
        generate_random_table_solo(batch_size, &ctx_b_hat, Direction::Right).collect();

    // 2. Run computations
    let mut x_1: Vec<ShuffleShare> = add_single_shares(add_single_shares(a, b), z_12).collect();
    apply_permutation(&pi_12, &mut x_1);

    let mut x_2: Vec<ShuffleShare> = add_single_shares(x_1, z_31).collect();
    apply_permutation(&pi_31, &mut x_2);

    send_to_peer(ctx, &OPRFShuffleStep::TransferX2, Direction::Right, x_2).await?;

    let res = combine_shares(a_hat, b_hat);
    Ok(res)
}

async fn run_h2<C, Sl, Sr, Zl, Zr>(
    ctx: &C,
    batch_size: u32,
    (_b, c): (Sl, Sr),
    (pi_12, pi_23): (Vec<u32>, Vec<u32>),
    (z_12, z_23): (Zl, Zr),
) -> Result<Vec<ShuffleInputRow>, Error>
where
    C: Context,
    Sl: IntoIterator<Item = ShuffleShare>,
    Sr: IntoIterator<Item = ShuffleShare>,
    Zl: IntoIterator<Item = ShuffleShare>,
    Zr: IntoIterator<Item = ShuffleShare>,
{
    // 1. Generate helper-specific random tables
    let ctx_b_hat = ctx.narrow(&OPRFShuffleStep::GenerateBHat);
    let b_hat: Vec<_> =
        generate_random_table_solo(batch_size, &ctx_b_hat, Direction::Left).collect();

    // 2. Run computations
    let mut y_1: Vec<ShuffleShare> = add_single_shares(c, z_12.into_iter()).collect();
    apply_permutation(&pi_12, &mut y_1);

    let ((), x_2) = future::try_join(
        send_to_peer(ctx, &OPRFShuffleStep::TransferY1, Direction::Right, y_1),
        receive_from_peer(
            ctx,
            &OPRFShuffleStep::TransferX2,
            Direction::Left,
            batch_size,
        ),
    )
    .await?;

    let mut x_3: Vec<_> = add_single_shares(x_2.into_iter(), z_23.into_iter()).collect();
    apply_permutation(&pi_23, &mut x_3);

    let c_hat_1: Vec<_> = add_single_shares(x_3.iter(), b_hat.iter()).collect();
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

    let c_hat = add_single_shares(c_hat_1.iter(), c_hat_2.iter());
    let res = combine_shares(b_hat, c_hat);
    Ok(res)
}

async fn run_h3<C, Sl, Sr, Zl, Zr>(
    ctx: &C,
    batch_size: u32,
    (_c, _a): (Sl, Sr),
    (pi_23, pi_31): (Vec<u32>, Vec<u32>),
    (z_23, z_31): (Zl, Zr),
) -> Result<Vec<ShuffleInputRow>, Error>
where
    C: Context,
    Sl: IntoIterator<Item = ShuffleShare>,
    Sr: IntoIterator<Item = ShuffleShare>,
    Zl: IntoIterator<Item = ShuffleShare>,
    Zr: IntoIterator<Item = ShuffleShare>,
{
    // 1. Generate helper-specific random tables
    let ctx_a_hat = ctx.narrow(&OPRFShuffleStep::GenerateAHat);
    let a_hat: Vec<_> =
        generate_random_table_solo(batch_size, &ctx_a_hat, Direction::Right).collect();

    // 2. Run computations
    let y_1 = receive_from_peer(
        ctx,
        &OPRFShuffleStep::TransferY1,
        Direction::Left,
        batch_size,
    )
    .await?;

    let mut y_2: Vec<ShuffleShare> = add_single_shares(y_1, z_31).collect();
    apply_permutation(&pi_31, &mut y_2);

    let mut y_3: Vec<ShuffleShare> = add_single_shares(y_2, z_23).collect();
    apply_permutation(&pi_23, &mut y_3);

    let c_hat_2 = add_single_shares(y_3.iter(), a_hat.iter()).collect::<Vec<_>>();
    let ((), c_hat_1) = future::try_join(
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

    let c_hat = add_single_shares(c_hat_1, c_hat_2);
    let res = combine_shares(c_hat, a_hat);
    Ok(res)
}

// --------------------------------------------------------------------------- //

fn split_shares(
    input_rows: &[ShuffleInputRow],
    direction: Direction,
) -> impl Iterator<Item = ShuffleShare> + '_ {
    let f = move |input_row| ShuffleShare::from_input_row(input_row, direction);
    input_rows.iter().map(f)
}

fn combine_shares<L, R>(l: L, r: R) -> Vec<ShuffleInputRow>
where
    L: IntoIterator<Item = ShuffleShare>,
    R: IntoIterator<Item = ShuffleShare>,
{
    l.into_iter()
        .zip(r)
        .map(|(l, r)| l.to_input_row(r))
        .collect::<Vec<_>>()
}

fn add_single_shares<'i, T, L, R>(l: L, r: R) -> impl Iterator<Item = T::Output> + 'i
where
    T: Add,
    L: IntoIterator<Item = T> + 'i,
    R: IntoIterator<Item = T> + 'i,
{
    l.into_iter().zip(r).map(|(a, b)| a + b)
}

// --------------------------------------------------------------------------- //

fn generate_random_tables_with_peers<C: Context>(
    batch_size: u32,
    narrow_ctx: &C,
) -> (
    impl Iterator<Item = ShuffleShare> + '_,
    impl Iterator<Item = ShuffleShare> + '_,
) {
    let (rng_l, rng_r) = narrow_ctx.prss_rng();
    let with_left = sample_iter(rng_l).take(batch_size as usize);
    let with_right = sample_iter(rng_r).take(batch_size as usize);
    (with_left, with_right)
}

fn generate_random_table_solo<C>(
    batch_size: u32,
    narrow_ctx: &C,
    peer: Direction,
) -> impl Iterator<Item = ShuffleShare> + '_
where
    C: Context,
{
    let rngs = narrow_ctx.prss_rng();
    let rng = match peer {
        Direction::Left => rngs.0,
        Direction::Right => rngs.1,
    };

    sample_iter(rng).take(batch_size as usize)
}

fn sample_iter<R: Rng>(rng: R) -> impl Iterator<Item = ShuffleShare> {
    rng.sample_iter(Standard)
}

// ---------------------------- helper communication ------------------------------------ //

async fn send_to_peer<C: Context, I: IntoIterator<Item = ShuffleShare>>(
    ctx: &C,
    step: &OPRFShuffleStep,
    direction: Direction,
    items: I,
) -> Result<(), Error> {
    let role = ctx.role().peer(direction);
    let send_channel = ctx.narrow(step).send_channel(role);
    for (record_id, row) in items.into_iter().enumerate() {
        send_channel.send(RecordId::from(record_id), row).await?;
    }
    Ok(())
}

async fn receive_from_peer<C: Context>(
    ctx: &C,
    step: &OPRFShuffleStep,
    direction: Direction,
    batch_size: u32,
) -> Result<Vec<ShuffleShare>, Error> {
    let role = ctx.role().peer(direction);
    let receive_channel: ReceivingEnd<ShuffleShare> = ctx.narrow(step).recv_channel(role);

    let mut output: Vec<ShuffleShare> = Vec::with_capacity(batch_size as usize);
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
