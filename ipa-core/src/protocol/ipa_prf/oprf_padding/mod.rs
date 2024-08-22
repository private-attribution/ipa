mod distributions;
mod insecure;
pub mod step;

use bitvec::view::BitViewSized;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
pub use insecure::DiscreteDp as InsecureDiscreteDp;
use rand::Rng;
use tokio::try_join;

use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA32, BA64},
        U128Conversions,
    },
    helpers::{Direction, Role, TotalRecords},
    protocol::{
        context::{prss::InstrumentedSequentialSharedRandomness, Context},
        ipa_prf::{
            boolean_ops::step::MultiplicationStep::Add,
            oprf_padding::{
                insecure::OPRFPaddingDp,
                step::{PaddingDpStep, SendTotalRows},
            },
            prf_sharding::AttributionOutputs,
            OPRFIPAInputRow,
        },
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        SecretSharing, SharedValue,
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

trait Paddable: Default {
    fn add_padding_items<V: Extend<Self>, C, const B: usize>(
        ctx: &C,
        h_i: Role,
        h_i_plus_one: Role,
        padding_input_rows: &mut V,
        padding_params: &PaddingParameters,
        rng: &mut InstrumentedSequentialSharedRandomness,
    ) -> Result<u32, Error>
    where
        C: Context;

    fn add_zero_shares<V: Extend<Self>>(padding_input_rows: &mut V, total_number_of_fake_rows: u32);
}

impl<BK, TV, TS> Paddable for OPRFIPAInputRow<BK, TV, TS>
where
    BK: BooleanArray + U128Conversions,
    TV: BooleanArray,
    TS: BooleanArray,
{
    fn add_padding_items<V: Extend<Self>, C, const B: usize>(
        ctx: &C,
        h_i: Role,
        h_i_plus_one: Role,
        padding_input_rows: &mut V,
        padding_params: &PaddingParameters,
        rng: &mut InstrumentedSequentialSharedRandomness,
    ) -> Result<u32, Error>
    where
        C: Context,
    {
        let mut total_number_of_fake_rows = 0;
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
                            let mut match_key_shares: AdditiveShare<BA64> =
                                AdditiveShare::default();
                            if ctx.role() == h_i {
                                match_key_shares = AdditiveShare::new(BA64::ZERO, dummy_mk);
                            }
                            if ctx.role() == h_i_plus_one {
                                match_key_shares = AdditiveShare::new(dummy_mk, BA64::ZERO);
                            }
                            let row = OPRFIPAInputRow {
                                match_key: match_key_shares,
                                is_trigger: AdditiveShare::new(Boolean::FALSE, Boolean::FALSE),
                                breakdown_key: AdditiveShare::new(BK::ZERO, BK::ZERO),
                                trigger_value: AdditiveShare::new(TV::ZERO, TV::ZERO),
                                timestamp: AdditiveShare::new(TS::ZERO, TS::ZERO),
                            };
                            padding_input_rows.push(row);
                        }
                    }
                }
            }
        }
        Ok(total_number_of_fake_rows)
    }

    fn add_zero_shares<V: Extend<Self>>(
        padding_input_rows: &mut V,
        total_number_of_fake_rows: u32,
    ) {
        for _ in 0..total_number_of_fake_rows as usize {
            let row = OPRFIPAInputRow {
                match_key: AdditiveShare::new(BA64::ZERO, BA64::ZERO),
                is_trigger: AdditiveShare::new(Boolean::FALSE, Boolean::FALSE),
                breakdown_key: AdditiveShare::new(BK::ZERO, BK::ZERO),
                trigger_value: AdditiveShare::new(TV::ZERO, TV::ZERO),
                timestamp: AdditiveShare::new(TS::ZERO, TS::ZERO),
            };

            padding_input_rows.push(row);
        }
    }
}

impl<BK, TV> Paddable for AttributionOutputs<AdditiveShare<BK>, AdditiveShare<TV>>
where
    BK: BooleanArray + U128Conversions,
    TV: BooleanArray,
{
    fn add_padding_items<V: Extend<Self>, C, const B: usize>(
        ctx: &C,
        h_i: Role,
        h_i_plus_one: Role,
        padding_input_rows: &mut V,
        padding_params: &PaddingParameters,
        rng: &mut InstrumentedSequentialSharedRandomness,
    ) -> Result<u32, Error>
    where
        C: Context,
    {
        // padding for aggregation
        let mut total_number_of_fake_rows = 0;
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
                // for every breakdown, sample how many dummies will be added
                for breakdownkey in 0..num_breakdowns {
                    let sample = aggregation_padding.sample(rng);
                    total_number_of_fake_rows += sample;

                    // now add `sample` many fake rows with this `breakdownkey`
                    for _ in 0..sample {
                        let mut breakdownkey_shares: AdditiveShare<BK> = AdditiveShare::default();
                        if ctx.role() == h_i {
                            breakdownkey_shares = AdditiveShare::new(
                                BK::ZERO,
                                BK::truncate_from(u128::from(breakdownkey)),
                            );
                        }
                        if ctx.role() == h_i_plus_one {
                            breakdownkey_shares = AdditiveShare::new(
                                BK::truncate_from(u128::from(breakdownkey)),
                                BK::ZERO,
                            );
                        }

                        let row = AttributionOutputs {
                            attributed_breakdown_key_bits: breakdownkey_shares,
                            capped_attributed_trigger_value: AdditiveShare::new(TV::ZERO, TV::ZERO),
                        };

                        padding_input_rows.push(row);
                    }
                }
            }
        }
        Ok(total_number_of_fake_rows)
    }

    fn add_zero_shares<V: Extend<Self>>(
        padding_input_rows: &mut V,
        total_number_of_fake_rows: u32,
    ) {
        for _ in 0..total_number_of_fake_rows as usize {
            let row = AttributionOutputs {
                attributed_breakdown_key_bits: AdditiveShare::new(BK::ZERO, BK::ZERO),
                capped_attributed_trigger_value: AdditiveShare::new(TV::ZERO, TV::ZERO),
            };

            padding_input_rows.push(row);
        }
    }
}

/// # Errors
/// Will propogate errors from `OPRFPaddingDp`
/// # Panics
/// Panics may happen in `apply_dp_padding_pass`
pub async fn apply_dp_padding<C, T, const B: usize>(
    ctx: C,
    mut input: Vec<T>,
    padding_params: PaddingParameters,
) -> Result<Vec<T>, Error>
where
    C: Context,
    T: Paddable,
    // V: BooleanArray + U128Conversions,
{
    let initial_len = input.len();

    // H1 and H2 add padding noise
    input = apply_dp_padding_pass::<C, T, B>(
        ctx.narrow(&PaddingDpStep::PaddingDpPass1),
        input,
        Role::H1,
        Role::H2,
        Role::H3,
        &padding_params,
    )
    .await?;

    // H3 and H1 add padding noise
    input = apply_dp_padding_pass::<C, T, B>(
        ctx.narrow(&PaddingDpStep::PaddingDpPass2),
        input,
        Role::H3,
        Role::H1,
        Role::H2,
        &padding_params,
    )
    .await?;

    // H2 and H3 add padding noise
    input = apply_dp_padding_pass::<C, T, B>(
        ctx.narrow(&PaddingDpStep::PaddingDpPass3),
        input,
        Role::H2,
        Role::H3,
        Role::H1,
        &padding_params,
    )
    .await?;

    let after_padding_len = input.len();
    tracing::info!(
        "Total number of padding records added: {}. Padding Parameters: {:?}",
        after_padding_len - initial_len,
        padding_params
    );

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
pub async fn apply_dp_padding_pass<C, T, const B: usize>(
    ctx: C,
    mut input: Vec<T>,
    h_i: Role,
    h_i_plus_one: Role,
    h_out: Role,
    padding_params: &PaddingParameters,
) -> Result<Vec<T>, Error>
where
    C: Context,
    T: Paddable,
    // I: SecretSharing<V>,
    // V: BooleanArray + U128Conversions,
{
    // assert roles are all unique
    assert!(h_i != h_i_plus_one);
    assert!(h_i != h_out);
    assert!(h_out != h_i_plus_one);

    let mut total_number_of_fake_rows = 0;
    let mut padding_input_rows: Vec<T> = Vec::new();

    // Step 1: Helpers `h_i` and `h_i_plus_one` will get the same rng from PRSS
    // and use it to sample the same random noise for padding from OPRFPaddingDp.
    // They will generate secret shares of these fake rows.
    if ctx.role() != h_out {
        total_number_of_fake_rows = two_parties_add_dummies::<C, T, B>(
            &ctx,
            &mut padding_input_rows,
            h_i,
            h_i_plus_one,
            padding_params,
        )?;
    }

    // Step 2: h_i and h_i_plus_one will send the send total_number_of_fake_rows to h_out. h_out will
    // check that both h_i and h_i_plus_one have sent the same value to prevent any malicious behavior
    // See oprf_padding/README.md for explanation of why revealing the total number of fake rows is okay.
    let send_ctx = ctx
        .narrow(&SendTotalRows::SendNumFakeRecords)
        .set_total_records(TotalRecords::ONE);
    match ctx.role() {
        role if role == h_i || role == h_i_plus_one => {
            let direction = if role == h_i {
                Direction::Left
            } else {
                Direction::Right
            };
            let send_channel = send_ctx.send_channel::<BA32>(send_ctx.role().peer(direction));
            let _ = send_channel
                .send(
                    RecordId::FIRST,
                    BA32::truncate_from(u128::from(total_number_of_fake_rows)),
                )
                .await;
        }
        _h_out => {
            let recv_channel_right =
                send_ctx.recv_channel::<BA32>(send_ctx.role().peer(Direction::Right));
            let recv_channel_left =
                send_ctx.recv_channel::<BA32>(send_ctx.role().peer(Direction::Left));
            let (from_right, from_left) = try_join!(
                async {
                    match recv_channel_right.receive(RecordId::FIRST).await {
                        Ok(v) => Ok::<u32, Error>(u32::try_from(v.as_u128()).unwrap()),
                        Err(e) => Err(e.into()),
                    }
                },
                async {
                    match recv_channel_left.receive(RecordId::FIRST).await {
                        Ok(v) => Ok::<u32, Error>(u32::try_from(v.as_u128()).unwrap()),
                        Err(e) => Err(e.into()),
                    }
                }
            )?;

            assert_eq!(from_right, from_left);
            total_number_of_fake_rows = from_right;
        }
    }

    // Step 3: `h_out` will set its shares to zero for the fake rows
    if ctx.role() == h_out {
        T::add_zero_shares(&mut padding_input_rows, total_number_of_fake_rows);
    }

    input.extend(padding_input_rows);
    Ok(input)
}

/// # Errors
/// Will propogate errors from `OPRFPaddingDp`
/// # Panics
///
pub fn two_parties_add_dummies<C, T, const B: usize>(
    ctx: &C,
    mut padding_input_rows: &mut Vec<T>,
    h_i: Role,
    h_i_plus_one: Role,
    padding_params: &PaddingParameters,
) -> Result<u32, Error>
where
    C: Context,
    T: Paddable,
    // I: SecretSharing<V>,
    // V: BooleanArray + U128Conversions,
{
    assert!(h_i != h_i_plus_one);
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

    total_number_of_fake_rows = T::add_padding_items(
        &ctx,
        h_i,
        h_i_plus_one,
        &mut padding_input_rows,
        padding_params,
        &mut rng,
    );

    Ok(total_number_of_fake_rows)
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

    pub fn expected_number_fake_rows(
        padding_params: PaddingParameters,
        num_breakdown_keys: u32,
    ) -> (f64, f64) {
        // print out how many fake rows are expected for both oprf and aggregation
        // for the given parameter set.
        let mut expected_agg_total_rows = 0.0;
        let mut expected_oprf_total_rows = 0.0;

        // padding for aggregation
        match padding_params.aggregation_padding {
            AggregationPadding::NoAggPadding => {
                expected_agg_total_rows = 0.0;
            }
            AggregationPadding::Parameters {
                aggregation_epsilon,
                aggregation_delta,
                aggregation_padding_sensitivity,
            } => {
                let aggregation_padding = OPRFPaddingDp::new(
                    aggregation_epsilon,
                    aggregation_delta,
                    aggregation_padding_sensitivity,
                )
                .unwrap();

                let (mean, _) = aggregation_padding.mean_and_std_bound();
                expected_agg_total_rows += f64::from(num_breakdown_keys) * mean;
            }
        }

        // padding for oprf
        match padding_params.oprf_padding {
            OPRFPadding::NoOPRFPadding => expected_oprf_total_rows = 0.0,
            OPRFPadding::Parameters {
                oprf_epsilon,
                oprf_delta,
                matchkey_cardinality_cap,
                oprf_padding_sensitivity,
            } => {
                let oprf_padding =
                    OPRFPaddingDp::new(oprf_epsilon, oprf_delta, oprf_padding_sensitivity).unwrap();

                let (mean, _) = oprf_padding.mean_and_std_bound();
                for cardinality in 0..matchkey_cardinality_cap {
                    expected_oprf_total_rows += mean * f64::from(cardinality);
                }
            }
        }
        (expected_oprf_total_rows, expected_agg_total_rows)
    }

    #[test]
    pub fn table_of_padding_parameters() {
        // see output https://docs.google.com/spreadsheets/d/1N0WEUkarP_6nd-7W8O9r-Xurh9OImESgAC1Jd_6OfWw/edit?gid=0#gid=0
        let epsilon_values = [0.01, 0.1, 1.0, 5.0, 10.0];
        let delta_values = [1e-9, 1e-8, 1e-7, 1e-6];
        let matchkey_cardinality_cap_values = [10, 100, 1000];
        let num_breakdown_keys_values = [16, 64, 256, 1024];
        println!(
            "epsilon, delta, matchkey_cardinality_cap,aggregation_padding_sensitivity,num_breakdown_keys,Expected \
            OPRF total rows,Expected Aggregation total rows ",
        );
        for epsilon in epsilon_values {
            for delta in delta_values {
                for matchkey_cardinality_cap in matchkey_cardinality_cap_values {
                    let aggregation_padding_sensitivity = matchkey_cardinality_cap;
                    for num_breakdown_keys in num_breakdown_keys_values {
                        let padding_params = PaddingParameters {
                            aggregation_padding: AggregationPadding::Parameters {
                                aggregation_epsilon: epsilon,
                                aggregation_delta: delta,
                                aggregation_padding_sensitivity,
                            },
                            oprf_padding: OPRFPadding::Parameters {
                                oprf_epsilon: epsilon,
                                oprf_delta: delta,
                                matchkey_cardinality_cap,
                                oprf_padding_sensitivity: 2,
                            },
                        };
                        // Call the function to get expected number of fake rows
                        let (expected_oprf_total_rows, expected_agg_total_rows) =
                            expected_number_fake_rows(padding_params, num_breakdown_keys);
                        // Print parameters and outcomes
                        println!(
                            "{epsilon}, {delta}, {matchkey_cardinality_cap},\
                            {aggregation_padding_sensitivity},{num_breakdown_keys},\
                            {expected_oprf_total_rows},{expected_agg_total_rows}"
                        );
                    }
                }
            }
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
