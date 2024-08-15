mod distributions;
mod insecure;
pub mod step;

#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
pub use insecure::DiscreteDp as InsecureDiscreteDp;
use rand::Rng;

use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA32, BA64},
        U128Conversions,
    },
    helpers::{Direction, Role, TotalRecords},
    protocol::{
        context::Context,
        ipa_prf::{
            oprf_padding::{
                insecure::OPRFPaddingDp,
                step::{PaddingDpStep, SendTotalRows},
            },
            OPRFIPAInputRow,
        },
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        SharedValue,
    },
};

/// Parameter struct for padding parameters.
#[derive(Default, Copy, Clone, Debug)]
pub struct PaddingParameters {
    pub aggregation_padding: AggregationPadding,
    pub oprf_padding: OPRFPadding,
}

#[derive(Copy, Clone, Debug)]
pub enum AggregationPadding {
    NoAggPadding,
    Parameters {
        aggregation_epsilon: f64,
        aggregation_delta: f64,
        aggregation_padding_sensitivity: u32,
    },
}

#[derive(Copy, Clone, Debug)]
pub enum OPRFPadding {
    NoOPRFPadding,
    Parameters {
        oprf_epsilon: f64,
        oprf_delta: f64,
        matchkey_cardinality_cap: u32,
        oprf_padding_sensitivity: u32,
    },
}

impl Default for AggregationPadding {
    fn default() -> Self {
        AggregationPadding::Parameters {
            aggregation_epsilon: 5.0,
            aggregation_delta: 1e-6,
            aggregation_padding_sensitivity: 10, // for IPA is most natural to set
                                                 // equal to the matchkey_cardinality_cap
        }
    }
}

impl Default for OPRFPadding {
    fn default() -> Self {
        OPRFPadding::Parameters {
            oprf_epsilon: 5.0,
            oprf_delta: 1e-6,
            matchkey_cardinality_cap: 10,
            oprf_padding_sensitivity: 2, // should remain 2
        }
    }
}

impl PaddingParameters {
    #[must_use]
    pub fn relaxed() -> Self {
        PaddingParameters {
            aggregation_padding: AggregationPadding::Parameters {
                aggregation_epsilon: 10.0,
                aggregation_delta: 1e-4,
                aggregation_padding_sensitivity: 3,
            },
            oprf_padding: OPRFPadding::Parameters {
                oprf_epsilon: 10.0,
                oprf_delta: 1e-4,
                matchkey_cardinality_cap: 3,
                oprf_padding_sensitivity: 2,
            },
        }
    }

    #[must_use]
    pub fn no_padding() -> Self {
        PaddingParameters {
            aggregation_padding: AggregationPadding::NoAggPadding,
            oprf_padding: OPRFPadding::NoOPRFPadding,
        }
    }
}

/// # Errors
/// Will propogate errors from `OPRFPaddingDp`
/// # Panics
/// Panics may happen in `apply_dp_padding_pass`
pub async fn apply_dp_padding<C, BK, TV, TS, const B: usize>(
    ctx: C,
    mut input: Vec<OPRFIPAInputRow<BK, TV, TS>>,
    padding_params: PaddingParameters,
) -> Result<Vec<OPRFIPAInputRow<BK, TV, TS>>, Error>
where
    C: Context,
    BK: BooleanArray + U128Conversions,
    TV: BooleanArray,
    TS: BooleanArray,
{
    // H1 and H2 add padding noise
    input = apply_dp_padding_pass::<C, BK, TV, TS, B>(
        ctx.narrow(&PaddingDpStep::PaddingDpPass1),
        input,
        Role::H1,
        Role::H2,
        Role::H3,
        &padding_params,
    )
    .await?;

    // H3 and H1 add padding noise
    input = apply_dp_padding_pass::<C, BK, TV, TS, B>(
        ctx.narrow(&PaddingDpStep::PaddingDpPass2),
        input,
        Role::H3,
        Role::H1,
        Role::H2,
        &padding_params,
    )
    .await?;

    // H2 and H3 add padding noise
    input = apply_dp_padding_pass::<C, BK, TV, TS, B>(
        ctx.narrow(&PaddingDpStep::PaddingDpPass3),
        input,
        Role::H2,
        Role::H3,
        Role::H1,
        &padding_params,
    )
    .await?;

    Ok(input)
}

/// Apply dp padding with one pair of helpers generating the noise
/// Steps
///     1.  Helpers `h_i` and `h_i_plus_one` will get the same rng from PRSS
///         and use it to sample the same random noise for padding from `OPRFPaddingDp`.
///         They will generate secret shares of these fake rows.
///     2.  `h_i` and `h_i_plus_one` will send the send `total_number_of_fake_rows` to `h_out`
///     3.  `h_out` will generate secret shares of zero for as many rows as the `total_number_of_fake_rows`
///
/// # Errors
/// Will propogate errors from `OPRFPaddingDp`
/// # Panics
/// Will panic if called with Roles which are not all unique
pub async fn apply_dp_padding_pass<C, BK, TV, TS, const B: usize>(
    ctx: C,
    mut input: Vec<OPRFIPAInputRow<BK, TV, TS>>,
    h_i: Role,
    h_i_plus_one: Role,
    h_out: Role,
    padding_params: &PaddingParameters,
) -> Result<Vec<OPRFIPAInputRow<BK, TV, TS>>, Error>
where
    C: Context,
    BK: BooleanArray + U128Conversions,
    TV: BooleanArray,
    TS: BooleanArray,
{
    // assert roles are all unique
    assert!(h_i != h_i_plus_one);
    assert!(h_i != h_out);
    assert!(h_out != h_i_plus_one);

    let mut total_number_of_fake_rows = 0;
    let mut padding_input_rows: Vec<OPRFIPAInputRow<BK, TV, TS>> = Vec::new();

    // Step 1: Helpers `h_i` and `h_i_plus_one` will get the same rng from PRSS
    // and use it to sample the same random noise for padding from OPRFPaddingDp.
    // They will generate secret shares of these fake rows.
    if ctx.role() != h_out {
        total_number_of_fake_rows = two_parties_add_dummies::<C, BK, TV, TS, B>(
            &ctx,
            &mut padding_input_rows,
            h_i,
            h_i_plus_one,
            padding_params,
        )?;
    }

    // Step 2: h_i and h_i_plus_one will send the send total_number_of_fake_rows to h_out
    let send_ctx = ctx
        .narrow(&SendTotalRows::SendFakeNumRecords)
        .set_total_records(TotalRecords::ONE);
    if ctx.role() == h_i {
        let send_channel = send_ctx.send_channel::<BA32>(send_ctx.role().peer(Direction::Left));
        let _ = send_channel
            .send(
                RecordId::FIRST,
                BA32::truncate_from(u128::from(total_number_of_fake_rows)),
            )
            .await;
    }
    if ctx.role() == h_i_plus_one {
        let send_channel = send_ctx.send_channel::<BA32>(send_ctx.role().peer(Direction::Right));
        let _ = send_channel
            .send(
                RecordId::FIRST,
                BA32::truncate_from(u128::from(total_number_of_fake_rows)),
            )
            .await;
    }
    if ctx.role() == h_out {
        // receive `total_number_of_fake_rows` from both other helpers and make sure they are the same
        let recv_channel_right =
            send_ctx.recv_channel::<BA32>(send_ctx.role().peer(Direction::Right));
        let from_right = match recv_channel_right.receive(RecordId::FIRST).await {
            Ok(v) => u32::try_from(v.as_u128()).unwrap(),
            Err(e) => return Err(e.into()),
        };

        let recv_channel_left =
            send_ctx.recv_channel::<BA32>(send_ctx.role().peer(Direction::Left));
        let from_left = match recv_channel_left.receive(RecordId::FIRST).await {
            Ok(v) => u32::try_from(v.as_u128()).unwrap(),
            Err(e) => return Err(e.into()),
        };
        assert_eq!(from_right, from_left);
        total_number_of_fake_rows = from_right;
    }

    // Step 3: `h_out` will generate secret shares of zero for as many rows as the `total_number_of_fake_rows`
    if ctx.role() == h_out {
        for _ in 0..total_number_of_fake_rows as usize {
            let row = OPRFIPAInputRow {
                match_key: Replicated::new(BA64::ZERO, BA64::ZERO),
                is_trigger: Replicated::new(Boolean::FALSE, Boolean::FALSE),
                breakdown_key: Replicated::new(BK::ZERO, BK::ZERO),
                trigger_value: Replicated::new(TV::ZERO, TV::ZERO),
                timestamp: Replicated::new(TS::ZERO, TS::ZERO),
            };
            padding_input_rows.push(row);
        }
    }

    input.extend(padding_input_rows);
    Ok(input)
}

/// # Errors
/// Will propogate errors from `OPRFPaddingDp`
/// # Panics
///
pub fn two_parties_add_dummies<C, BK, TV, TS, const B: usize>(
    ctx: &C,
    padding_input_rows: &mut Vec<OPRFIPAInputRow<BK, TV, TS>>,
    h_i: Role,
    h_i_plus_one: Role,
    padding_params: &PaddingParameters,
) -> Result<u32, Error>
where
    C: Context,
    BK: BooleanArray + U128Conversions,
    TV: BooleanArray,
    TS: BooleanArray,
{
    let mut total_number_of_fake_rows = 0;
    let (mut left, mut right) = ctx.prss_rng();
    // The first is shared with the helper to the "left", the second is shared with the helper to the "right".
    let mut rng = &mut right;
    if ctx.role() == h_i {
        rng = &mut right;
    }
    if ctx.role() == h_i_plus_one {
        rng = &mut left;
    }

    // padding for oprf
    match padding_params.oprf_padding {
        OPRFPadding::NoOPRFPadding => {}
        OPRFPadding::Parameters {
            oprf_epsilon,
            oprf_delta,
            matchkey_cardinality_cap,
            oprf_padding_sensitivity,
        } => {
            let oprf_padding =
                OPRFPaddingDp::new(oprf_epsilon, oprf_delta, oprf_padding_sensitivity)?;
            for cardinality in 1..=matchkey_cardinality_cap {
                let sample = oprf_padding.sample(rng);
                total_number_of_fake_rows += sample * cardinality;

                // this means there will be `sample` many unique
                // matchkeys to add each with cardinality = `cardinality`
                for _ in 0..sample {
                    let dummy_mk: BA64 = rng.gen();
                    for _ in 0..cardinality {
                        let mut match_key_shares: Replicated<BA64> = Replicated::default();
                        if ctx.role() == h_i {
                            match_key_shares = Replicated::new(BA64::ZERO, dummy_mk);
                        }
                        if ctx.role() == h_i_plus_one {
                            match_key_shares = Replicated::new(dummy_mk, BA64::ZERO);
                        }
                        let row = OPRFIPAInputRow {
                            match_key: match_key_shares,
                            is_trigger: Replicated::new(Boolean::FALSE, Boolean::FALSE),
                            breakdown_key: Replicated::new(BK::ZERO, BK::ZERO),
                            trigger_value: Replicated::new(TV::ZERO, TV::ZERO),
                            timestamp: Replicated::new(TS::ZERO, TS::ZERO),
                        };
                        padding_input_rows.push(row);
                    }
                }
            }
        }
    }

    // padding for aggregation
    match padding_params.aggregation_padding {
        AggregationPadding::NoAggPadding => {}
        AggregationPadding::Parameters {
            aggregation_epsilon,
            aggregation_delta,
            aggregation_padding_sensitivity,
        } => {
            let aggregation_padding = OPRFPaddingDp::new(
                aggregation_epsilon,
                aggregation_delta,
                aggregation_padding_sensitivity,
            )?;
            let num_breakdowns: u32 = u32::try_from(B).unwrap();
            // // for every breakdown, sample how many dummies will be added
            for breakdownkey in 0..num_breakdowns {
                let sample = aggregation_padding.sample(rng);
                total_number_of_fake_rows += sample;

                // now add `sample` many fake rows with this `breakdownkey`
                // These fake rows need to have random matchkeys, but we don't want to have any with
                // cardinality 1 or they may be dropped after matching.  So instead we add with the
                // following cardinalities:
                //  - in the case `sample` is even, all matchkeys have cardinality 2
                //  - in the case `sample` is odd, all matchkeys have cardinality 2 except one set
                //    of cardinality 3.
                //  - in the case `sample` = 1, we add a matchkey of cardinality 1.
                //
                // consider the division algorithm of sample: sample = 2 q + r such that 0 <= r < 2
                let (q, r) = (sample / 2, sample % 2);
                let mut dummy_mk: BA64 = rng.gen();
                for _ in 0..q {
                    dummy_mk = rng.gen();
                    for _ in 0..2 {
                        let row = create_aggregation_fake_row::<C, BK, TV, TS, B>(
                            ctx,
                            h_i,
                            h_i_plus_one,
                            dummy_mk,
                            breakdownkey,
                        )?;
                        padding_input_rows.push(row);
                    }
                }
                if r == 1 {
                    let row = create_aggregation_fake_row::<C, BK, TV, TS, B>(
                        ctx,
                        h_i,
                        h_i_plus_one,
                        dummy_mk,
                        breakdownkey,
                    )?;
                    padding_input_rows.push(row);
                }
            }
        }
    }
    Ok(total_number_of_fake_rows)
}
/// # Errors
/// no unwraps here so unlikely to propagate an error.
pub fn create_aggregation_fake_row<C, BK, TV, TS, const B: usize>(
    ctx: &C,
    h_i: Role,
    h_i_plus_one: Role,
    dummy_mk: BA64,
    breakdownkey: u32,
) -> Result<OPRFIPAInputRow<BK, TV, TS>, Error>
where
    C: Context,
    BK: BooleanArray + U128Conversions,
    TV: BooleanArray,
    TS: BooleanArray,
{
    let mut match_key_shares: Replicated<BA64> = Replicated::default();
    if ctx.role() == h_i {
        match_key_shares = Replicated::new(BA64::ZERO, dummy_mk);
    }
    if ctx.role() == h_i_plus_one {
        match_key_shares = Replicated::new(dummy_mk, BA64::ZERO);
    }

    let mut breakdownkey_shares: Replicated<BK> = Replicated::default();
    if ctx.role() == h_i {
        breakdownkey_shares =
            Replicated::new(BK::ZERO, BK::truncate_from(u128::from(breakdownkey)));
    }
    if ctx.role() == h_i_plus_one {
        breakdownkey_shares =
            Replicated::new(BK::truncate_from(u128::from(breakdownkey)), BK::ZERO);
    }
    let row = OPRFIPAInputRow {
        match_key: match_key_shares,
        is_trigger: Replicated::new(Boolean::FALSE, Boolean::FALSE),
        breakdown_key: breakdownkey_shares,
        trigger_value: Replicated::new(TV::ZERO, TV::ZERO),
        timestamp: Replicated::new(TS::ZERO, TS::ZERO),
    };
    Ok(row)
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use crate::{
        error::Error,
        ff::{
            boolean_array::{BooleanArray, BA20, BA3, BA32, BA8},
            U128Conversions,
        },
        helpers::{Direction, Role, TotalRecords},
        protocol::{
            context::Context,
            ipa_prf::{
                oprf_padding::{
                    apply_dp_padding_pass, insecure, insecure::OPRFPaddingDp, AggregationPadding,
                    OPRFPadding, PaddingParameters,
                },
                OPRFIPAInputRow,
            },
            RecordId,
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    pub async fn set_up_apply_dp_padding_pass<C, BK, TV, TS, const B: usize>(
        ctx: C,
        padding_params: PaddingParameters,
    ) -> Result<Vec<OPRFIPAInputRow<BK, TV, TS>>, Error>
    where
        C: Context,
        BK: BooleanArray + U128Conversions,
        TV: BooleanArray,
        TS: BooleanArray,
    {
        let mut input: Vec<OPRFIPAInputRow<BK, TV, TS>> = Vec::new();
        input = apply_dp_padding_pass::<C, BK, TV, TS, B>(
            ctx,
            input,
            Role::H1,
            Role::H2,
            Role::H3,
            &padding_params,
        )
        .await?;
        Ok(input)
    }

    #[tokio::test]
    pub async fn oprf_noise_in_dp_padding_pass() {
        type BK = BA8;
        type TV = BA3;
        type TS = BA20;
        const B: usize = 256;
        let world = TestWorld::default();
        let oprf_epsilon = 1.0;
        let oprf_delta = 1e-6;
        let matchkey_cardinality_cap = 10;
        let oprf_padding_sensitivity = 2;

        let result = world
            .semi_honest((), |ctx, ()| async move {
                let padding_params = PaddingParameters {
                    oprf_padding: OPRFPadding::Parameters {
                        oprf_epsilon,
                        oprf_delta,
                        matchkey_cardinality_cap,
                        oprf_padding_sensitivity,
                    },
                    aggregation_padding: AggregationPadding::NoAggPadding,
                };
                set_up_apply_dp_padding_pass::<_, BK, TV, TS, B>(ctx, padding_params).await
            })
            .await
            .map(Result::unwrap);
        // check that all three helpers added the same number of dummy shares
        assert!(result[0].len() == result[1].len() && result[0].len() == result[2].len());

        let result_reconstructed = result.reconstruct();
        // check that all fields besides the matchkey are zero and matchkey is not zero
        let mut user_id_counts: HashMap<u64, u32> = HashMap::new();
        for row in result_reconstructed {
            // println!("{row:?}");
            assert!(row.timestamp == 0);
            assert!(row.trigger_value == 0);
            assert!(!row.is_trigger_report);
            assert!(row.breakdown_key == 0); // since we set AggregationPadding::NoAggPadding
            assert!(row.user_id != 0);

            let count = user_id_counts.entry(row.user_id).or_insert(0);
            *count += 1;
        }
        // Now look at now many times a user_id occured
        let mut sample_per_cardinality: BTreeMap<u32, u32> = BTreeMap::new();
        for cardinality in user_id_counts.values() {
            let count = sample_per_cardinality.entry(*cardinality).or_insert(0);
            *count += 1;
        }
        let mut distribution_of_samples: BTreeMap<u32, u32> = BTreeMap::new();

        for (cardinality, sample) in sample_per_cardinality {
            println!("{sample} user IDs occurred {cardinality} time(s)");
            let count = distribution_of_samples.entry(sample).or_insert(0);
            *count += 1;
        }

        let oprf_padding =
            OPRFPaddingDp::new(oprf_epsilon, oprf_delta, oprf_padding_sensitivity).unwrap();

        let (mean, std_bound) = oprf_padding.mean_and_std_bound();
        assert!(std_bound > 1.0); // bound on the std only holds if this is true.
        println!("mean = {mean}, std_bound = {std_bound}");
        for (sample, count) in &distribution_of_samples {
            println!("An OPRFPadding sample value equal to {sample} occurred {count} time(s)",);
            assert!(
                (f64::from(*sample) - mean).abs() < 5.0 * std_bound,
                "aggregation noise sample was not within 5 times the standard deviation bound from what was expected."
            );
        }
    }

    #[tokio::test]
    pub async fn aggregation_noise_in_dp_padding_pass() {
        type BK = BA8;
        type TV = BA3;
        type TS = BA20;
        const B: usize = 256;
        let world = TestWorld::default();
        let aggregation_epsilon = 1.0;
        let aggregation_delta = 1e-6;
        let aggregation_padding_sensitivity = 2;

        let result = world
            .semi_honest((), |ctx, ()| async move {
                let padding_params = PaddingParameters {
                    oprf_padding: OPRFPadding::NoOPRFPadding,
                    aggregation_padding: AggregationPadding::Parameters {
                        aggregation_epsilon,
                        aggregation_delta,
                        aggregation_padding_sensitivity,
                    },
                };
                set_up_apply_dp_padding_pass::<_, BK, TV, TS, B>(ctx, padding_params).await
            })
            .await
            .map(Result::unwrap);

        // check that all three helpers added the same number of dummy shares
        assert!(result[0].len() == result[1].len() && result[0].len() == result[2].len());

        let result_reconstructed = result.reconstruct();

        // check that all fields besides the matchkey and breakdownkey are zero and matchkey is not zero
        let mut user_id_counts: HashMap<u64, u32> = HashMap::new();
        let mut sample_per_breakdown: HashMap<u32, u32> = HashMap::new();
        for row in result_reconstructed {
            assert!(row.timestamp == 0);
            assert!(row.trigger_value == 0);
            assert!(!row.is_trigger_report);
            assert!(row.user_id != 0);

            let count = user_id_counts.entry(row.user_id).or_insert(0);
            *count += 1;

            let sample = sample_per_breakdown.entry(row.breakdown_key).or_insert(0);
            *sample += 1;
        }
        // check that all breakdowns had noise added
        assert!(B == sample_per_breakdown.len());

        // Now look at now many times a user_id occured
        let mut number_per_cardinality: BTreeMap<u32, u32> = BTreeMap::new();
        for cardinality in user_id_counts.values() {
            let count = number_per_cardinality.entry(*cardinality).or_insert(0);
            *count += 1;
            assert!(*cardinality == 1 || *cardinality == 2 || *cardinality == 3);
        }

        let aggregation_padding = OPRFPaddingDp::new(
            aggregation_epsilon,
            aggregation_delta,
            aggregation_padding_sensitivity,
        )
        .unwrap();

        let (mean, std_bound) = aggregation_padding.mean_and_std_bound();
        assert!(std_bound > 1.0); // bound on the std only holds if this is true.
        println!("mean = {mean}, std_bound = {std_bound}");
        for sample in sample_per_breakdown.values() {
            assert!(
                (f64::from(*sample) - mean).abs() < 5.0 * std_bound,
                "aggregation noise sample was not within 5 times the standard deviation bound from what was expected."
            );
        }
    }

    /// Below tests are for more foundational components used in building padding.

    /// # Errors
    /// Will propogate errors from `OPRFPaddingDp`
    pub fn sample_shared_randomness<C>(ctx: &C) -> Result<u32, insecure::Error>
    where
        C: Context,
    {
        let oprf_padding = OPRFPaddingDp::new(1.0, 1e-6, 10_u32)?;
        let (mut left, mut right) = ctx.prss_rng();
        let rng = if ctx.role() == Role::H1 {
            &mut right
        } else if ctx.role() == Role::H2 {
            &mut left
        } else {
            return Ok(0);
        };
        let sample = oprf_padding.sample(rng);
        Ok(sample)
    }

    #[tokio::test]
    pub async fn test_sample_shared_randomness() {
        println!("in test_sample_shared_randomness");
        let world = TestWorld::default();
        let result = world
            .semi_honest(
                (),
                |ctx, ()| async move { sample_shared_randomness::<_>(&ctx) },
            )
            .await;
        assert!(result[0] == result[1]); // H1 and H2 should agree
        println!("result = {result:?}",);
    }

    pub async fn send_to_helper<C>(ctx: C) -> Result<BA32, Error>
    where
        C: Context,
    {
        let mut num_fake_rows: BA32 = BA32::truncate_from(u128::try_from(0).unwrap());

        if ctx.role() == Role::H1 {
            num_fake_rows = BA32::truncate_from(u128::try_from(2).unwrap());
        }
        if ctx.role() == Role::H2 {
            num_fake_rows = BA32::truncate_from(u128::try_from(3).unwrap());
        }
        let send_ctx = ctx.set_total_records(TotalRecords::ONE);
        if ctx.role() == Role::H1 {
            let send_channel = send_ctx.send_channel::<BA32>(send_ctx.role().peer(Direction::Left));
            let _ = send_channel.send(RecordId::FIRST, num_fake_rows).await;
        }

        if ctx.role() == Role::H3 {
            let recv_channel =
                send_ctx.recv_channel::<BA32>(send_ctx.role().peer(Direction::Right));
            match recv_channel.receive(RecordId::FIRST).await {
                Ok(v) => num_fake_rows = v,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(num_fake_rows)
    }

    #[tokio::test]
    pub async fn test_send_to_helper() {
        let world = TestWorld::default();
        let result = world
            .semi_honest((), |ctx, ()| async move { send_to_helper::<_>(ctx).await })
            .await;
        println!("result = {result:?}",);
        let value_h1 = result[0].as_ref().expect("Failed to get result for H1");
        let value_h3 = result[2].as_ref().expect("Failed to get result for H3");
        assert_eq!(value_h1, value_h3, "H1 and H3 should agree");
    }
}
