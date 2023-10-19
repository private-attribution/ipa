use std::ops::Add;

use futures::future;
use generic_array::GenericArray;
use ipa_macros::Step;
use rand::{distributions::Standard, seq::SliceRandom, Rng};
use typenum::Unsigned;

use super::{context::Context, ipa::IPAInputRow, RecordId};
use crate::{
    error::Error,
    ff::{Field, Gf32Bit, Gf40Bit, Gf8Bit, Serializable},
    helpers::{query::oprf_shuffle::QueryConfig, Direction, Message, ReceivingEnd, Role},
};

type OprfMK = Gf40Bit;
type OprfBK = Gf8Bit;
type OprfF = Gf32Bit;

pub type OPRFInputRow = IPAInputRow<OprfF, OprfMK, OprfBK>;

#[derive(Debug, Clone, Copy)]
pub struct OPRFShuffleSingleShare {
    pub timestamp: OprfF,
    pub mk: OprfMK,
    pub is_trigger_bit: OprfF,
    pub breakdown_key: OprfBK,
    pub trigger_value: OprfF,
}

impl OPRFShuffleSingleShare {
    #[must_use]
    pub fn from_input_row(input_row: &OPRFInputRow, shared_with: Direction) -> Self {
        match shared_with {
            Direction::Left => Self {
                timestamp: input_row.timestamp.as_tuple().1,
                mk: input_row.mk_shares.as_tuple().1,
                is_trigger_bit: input_row.is_trigger_bit.as_tuple().1,
                breakdown_key: input_row.breakdown_key.as_tuple().1,
                trigger_value: input_row.trigger_value.as_tuple().1,
            },

            Direction::Right => Self {
                timestamp: input_row.timestamp.as_tuple().0,
                mk: input_row.mk_shares.as_tuple().0,
                is_trigger_bit: input_row.is_trigger_bit.as_tuple().0,
                breakdown_key: input_row.breakdown_key.as_tuple().0,
                trigger_value: input_row.trigger_value.as_tuple().0,
            },
        }
    }

    #[must_use]
    pub fn to_input_row(self, rhs: Self) -> OPRFInputRow {
        OPRFInputRow {
            timestamp: (self.timestamp, rhs.timestamp).into(),
            mk_shares: (self.mk, rhs.mk).into(),
            is_trigger_bit: (self.is_trigger_bit, rhs.is_trigger_bit).into(),
            breakdown_key: (self.breakdown_key, rhs.breakdown_key).into(),
            trigger_value: (self.trigger_value, rhs.trigger_value).into(),
        }
    }
}

impl rand::prelude::Distribution<OPRFShuffleSingleShare> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> OPRFShuffleSingleShare {
        OPRFShuffleSingleShare {
            timestamp: OprfF::truncate_from(rng.gen::<u128>()),
            mk: OprfMK::truncate_from(rng.gen::<u128>()),
            is_trigger_bit: OprfF::truncate_from(rng.gen::<u128>()),
            breakdown_key: OprfBK::truncate_from(rng.gen::<u128>()),
            trigger_value: OprfF::truncate_from(rng.gen::<u128>()),
        }
    }
}

impl Add for OPRFShuffleSingleShare {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl Add for &OPRFShuffleSingleShare {
    type Output = OPRFShuffleSingleShare;

    fn add(self, &rhs: Self) -> Self::Output {
        Self::Output {
            timestamp: self.timestamp + rhs.timestamp,
            mk: self.mk + rhs.mk,
            is_trigger_bit: self.is_trigger_bit + rhs.is_trigger_bit,
            breakdown_key: self.breakdown_key + rhs.breakdown_key,
            trigger_value: self.trigger_value + rhs.trigger_value,
        }
    }
}

impl Serializable for OPRFShuffleSingleShare {
    type Size = <<OprfF as Serializable>::Size as Add<
        <<OprfMK as Serializable>::Size as Add<
            <<OprfF as Serializable>::Size as Add<
                <<OprfBK as Serializable>::Size as Add<<OprfF as Serializable>::Size>>::Output,
            >>::Output,
        >>::Output,
    >>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let mk_sz = <OprfMK as Serializable>::Size::USIZE;
        let bk_sz = <OprfBK as Serializable>::Size::USIZE;
        let f_sz = <OprfF as Serializable>::Size::USIZE;

        self.timestamp
            .serialize(GenericArray::from_mut_slice(&mut buf[..f_sz]));
        self.mk
            .serialize(GenericArray::from_mut_slice(&mut buf[f_sz..f_sz + mk_sz]));
        self.is_trigger_bit.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz..f_sz + mk_sz + f_sz],
        ));
        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz + f_sz..f_sz + mk_sz + f_sz + bk_sz],
        ));
        self.trigger_value.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz + f_sz + bk_sz..],
        ));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let mk_sz = <OprfMK as Serializable>::Size::USIZE;
        let bk_sz = <OprfBK as Serializable>::Size::USIZE;
        let f_sz = <OprfF as Serializable>::Size::USIZE;

        let timestamp = OprfF::deserialize(GenericArray::from_slice(&buf[..f_sz]));
        let mk = OprfMK::deserialize(GenericArray::from_slice(&buf[f_sz..f_sz + mk_sz]));
        let is_trigger_bit = OprfF::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz..f_sz + mk_sz + f_sz],
        ));
        let breakdown_key = OprfBK::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz + f_sz..f_sz + mk_sz + f_sz + bk_sz],
        ));
        let trigger_value = OprfF::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz + f_sz + bk_sz..],
        ));
        Self {
            timestamp,
            mk,
            is_trigger_bit,
            breakdown_key,
            trigger_value,
        }
    }
}

impl Message for OPRFShuffleSingleShare {}

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
pub async fn oprf_shuffle<C: Context>(
    ctx: C,
    input_rows: &[OPRFInputRow],
    _config: QueryConfig,
) -> Result<Vec<OPRFInputRow>, Error> {
    let batch_size = u32::try_from(input_rows.len()).map_err(|_e| {
        Error::FieldValueTruncation(format!(
            "Cannot truncate the number of input rows {} to u32",
            input_rows.len(),
        ))
    })?;

    let share_l = split_shares(input_rows, Direction::Left);
    let share_r = split_shares(input_rows, Direction::Right);

    match ctx.role() {
        Role::H1 => run_h1(&ctx, batch_size, share_l, share_r).await,
        Role::H2 => run_h2(&ctx, batch_size, share_l, share_r).await,
        Role::H3 => run_h3(&ctx, batch_size, share_l, share_r).await,
    }
}

async fn run_h1<C, L, R>(ctx: &C, batch_size: u32, a: L, b: R) -> Result<Vec<OPRFInputRow>, Error>
where
    C: Context,
    L: IntoIterator<Item = OPRFShuffleSingleShare>,
    R: IntoIterator<Item = OPRFShuffleSingleShare>,
{
    // 1. Generate permutations
    let (pi_31, pi_12) = generate_permutations_with_peers(batch_size, ctx);

    // 2. Generate random tables
    let (z_31, z_12) = generate_random_tables_with_peers(batch_size, ctx);
    let a_hat = generate_random_table_solo(
        batch_size,
        ctx,
        &OPRFShuffleStep::GenerateAHat,
        Direction::Left,
    );
    let b_hat = generate_random_table_solo(
        batch_size,
        ctx,
        &OPRFShuffleStep::GenerateBHat,
        Direction::Right,
    );

    // 3. Run computations
    let mut x_1: Vec<OPRFShuffleSingleShare> =
        add_single_shares(add_single_shares(a, b), z_12).collect();
    apply(&pi_12, &mut x_1);

    let mut x_2: Vec<OPRFShuffleSingleShare> = add_single_shares(x_1.iter(), z_31.iter()).collect();
    apply(&pi_31, &mut x_2);

    send_to_peer(ctx, &OPRFShuffleStep::TransferX2, Direction::Right, x_2).await?;

    let res = combine_shares(a_hat, b_hat);
    Ok(res)
}

async fn run_h2<C, L, R>(ctx: &C, batch_size: u32, _b: L, c: R) -> Result<Vec<OPRFInputRow>, Error>
where
    C: Context,
    L: IntoIterator<Item = OPRFShuffleSingleShare>,
    R: IntoIterator<Item = OPRFShuffleSingleShare>,
{
    // 1. Generate permutations
    let (pi_12, pi_23) = generate_permutations_with_peers(batch_size, ctx);

    // 2. Generate random tables
    let (z_12, z_23) = generate_random_tables_with_peers(batch_size, ctx);
    let b_hat = generate_random_table_solo(
        batch_size,
        ctx,
        &OPRFShuffleStep::GenerateBHat,
        Direction::Left,
    );

    // 3. Run computations
    let mut y_1: Vec<OPRFShuffleSingleShare> = add_single_shares(c, z_12.into_iter()).collect();
    apply(&pi_12, &mut y_1);

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

    let mut x_3: Vec<OPRFShuffleSingleShare> =
        add_single_shares(x_2.into_iter(), z_23.into_iter()).collect();
    apply(&pi_23, &mut x_3);

    let c_hat_1 = add_single_shares(x_3.iter(), b_hat.iter()).collect::<Vec<_>>();
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

async fn run_h3<C, L, R>(ctx: &C, batch_size: u32, _c: L, _a: R) -> Result<Vec<OPRFInputRow>, Error>
where
    C: Context,
    L: IntoIterator<Item = OPRFShuffleSingleShare>,
    R: IntoIterator<Item = OPRFShuffleSingleShare>,
{
    // 1. Generate permutations
    let (pi_23, pi_31) = generate_permutations_with_peers(batch_size, ctx);

    // 2. Generate random tables
    let (z_23, z_31) = generate_random_tables_with_peers(batch_size, ctx);
    let a_hat = generate_random_table_solo(
        batch_size,
        ctx,
        &OPRFShuffleStep::GenerateAHat,
        Direction::Right,
    );

    // 3. Run computations
    let y_1 = receive_from_peer(
        ctx,
        &OPRFShuffleStep::TransferY1,
        Direction::Left,
        batch_size,
    )
    .await?;

    let mut y_2: Vec<OPRFShuffleSingleShare> = add_single_shares(y_1, z_31).collect();
    apply(&pi_31, &mut y_2);

    let mut y_3: Vec<OPRFShuffleSingleShare> = add_single_shares(y_2, z_23).collect();
    apply(&pi_23, &mut y_3);

    let c_hat_2 = add_single_shares(y_3, a_hat.clone()).collect::<Vec<_>>();
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
    input_rows: &[OPRFInputRow],
    direction: Direction,
) -> impl Iterator<Item = OPRFShuffleSingleShare> + '_ {
    let f = move |input_row| OPRFShuffleSingleShare::from_input_row(input_row, direction);
    input_rows.iter().map(f)
}

fn combine_shares<L, R>(l: L, r: R) -> Vec<OPRFInputRow>
where
    L: IntoIterator<Item = OPRFShuffleSingleShare>,
    R: IntoIterator<Item = OPRFShuffleSingleShare>,
{
    l.into_iter()
        .zip(r)
        .map(|(l, r)| l.to_input_row(r))
        .collect::<Vec<_>>()
}

fn add_single_shares<'a, T, L, R>(l: L, r: R) -> impl Iterator<Item = T::Output>
where
    T: Add + 'a,
    L: IntoIterator<Item = T>,
    R: IntoIterator<Item = T>,
{
    l.into_iter().zip(r).map(|(a, b)| a + b)
}

// --------------------------------------------------------------------------- //

fn generate_random_tables_with_peers<C: Context>(
    batch_size: u32,
    ctx: &C,
) -> (Vec<OPRFShuffleSingleShare>, Vec<OPRFShuffleSingleShare>) {
    let narrow_step = ctx.narrow(&OPRFShuffleStep::GenerateZ);
    let (rng_l, rng_r) = narrow_step.prss_rng();
    let with_left = sample_iter(rng_l).take(batch_size as usize).collect();
    let with_right = sample_iter(rng_r).take(batch_size as usize).collect();
    (with_left, with_right)
}

fn generate_random_table_solo<C>(
    batch_size: u32,
    ctx: &C,
    step: &OPRFShuffleStep,
    peer: Direction,
) -> Vec<OPRFShuffleSingleShare>
where
    C: Context,
{
    let narrow_step = ctx.narrow(step);
    let rngs = narrow_step.prss_rng();
    let mut rng = match peer {
        Direction::Left => rngs.0,
        Direction::Right => rngs.1,
    };

    sample_iter(&mut rng)
        .take(batch_size as usize)
        .collect::<Vec<_>>()
}

fn sample_iter<R: Rng>(rng: R) -> impl Iterator<Item = OPRFShuffleSingleShare> {
    rng.sample_iter(Standard)
}

// ---------------------------- helper communication ------------------------------------ //

async fn send_to_peer<C: Context, I: IntoIterator<Item = OPRFShuffleSingleShare>>(
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
) -> Result<Vec<OPRFShuffleSingleShare>, Error> {
    let role = ctx.role().peer(direction);
    let receive_channel: ReceivingEnd<OPRFShuffleSingleShare> = ctx.narrow(step).recv_channel(role);

    let mut output: Vec<OPRFShuffleSingleShare> = Vec::with_capacity(batch_size as usize);
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

use bitvec::bitvec;
use embed_doc_image::embed_doc_image;

#[embed_doc_image("apply", "images/sort/apply.png")]
/// Permutation reorders (1, 2, . . . , m) into (σ(1), σ(2), . . . , σ(m)).
/// For example, if σ(1) = 2, σ(2) = 3, σ(3) = 1, and σ(4) = 0, an input (A, B, C, D) is reordered into (C, D, B, A) by σ.
///
/// ![Apply steps][apply]
fn apply<T>(permutation: &[u32], values: &mut [T]) {
    // NOTE: This is copypasta from crate::protocol::sort
    debug_assert!(permutation.len() == values.len());
    let mut permuted = bitvec![0; permutation.len()];

    for i in 0..permutation.len() {
        if !permuted[i] {
            let mut pos_i = i;
            let mut pos_j = permutation[pos_i] as usize;
            while pos_j != i {
                values.swap(pos_i, pos_j);
                permuted.set(pos_j, true);
                pos_i = pos_j;
                pos_j = permutation[pos_i] as usize;
            }
        }
    }
}
