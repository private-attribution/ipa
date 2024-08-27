mod distributions;
pub mod insecure;
pub mod step;

#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
pub use insecure::DiscreteDp as InsecureDiscreteDp;
use rand::Rng;
use tokio::try_join;

use crate::{
    error,
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

/// Paddable trait to support generation of padding for both `OPRFIPAInputRow`s and `AttributionOutputs`
/// while reusing the code common to both.
pub trait Paddable {
    /// # Errors
    /// may propagate errors from `OPRFPaddingDp` distribution setup
    fn add_padding_items<V: Extend<Self>, const B: usize>(
        direction_to_excluded_helper: Direction,
        padding_input_rows: &mut V,
        padding_params: &PaddingParameters,
        rng: &mut InstrumentedSequentialSharedRandomness,
    ) -> Result<u32, Error>
    where
        Self: Sized;

    fn add_zero_shares<V: Extend<Self>>(padding_input_rows: &mut V, total_number_of_fake_rows: u32)
    where
        Self: Sized;
}

impl<BK, TV, TS> Paddable for OPRFIPAInputRow<BK, TV, TS>
where
    BK: BooleanArray + U128Conversions,
    TV: BooleanArray,
    TS: BooleanArray,
{
    fn add_padding_items<V: Extend<Self>, const B: usize>(
        direction_to_excluded_helper: Direction,
        padding_input_rows: &mut V,
        padding_params: &PaddingParameters,
        rng: &mut InstrumentedSequentialSharedRandomness,
    ) -> Result<u32, Error> {
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
                            let match_key_shares = match direction_to_excluded_helper {
                                Direction::Left => AdditiveShare::new(BA64::ZERO, dummy_mk),
                                Direction::Right => AdditiveShare::new(dummy_mk, BA64::ZERO),
                            };
                            let row = OPRFIPAInputRow {
                                match_key: match_key_shares,
                                is_trigger: AdditiveShare::new(Boolean::FALSE, Boolean::FALSE),
                                breakdown_key: AdditiveShare::new(BK::ZERO, BK::ZERO),
                                trigger_value: AdditiveShare::new(TV::ZERO, TV::ZERO),
                                timestamp: AdditiveShare::new(TS::ZERO, TS::ZERO),
                            };
                            padding_input_rows.extend(std::iter::once(row));
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

            padding_input_rows.extend(std::iter::once(row));
        }
    }
}

impl<BK, TV> Paddable for AttributionOutputs<AdditiveShare<BK>, AdditiveShare<TV>>
where
    BK: BooleanArray + U128Conversions,
    TV: BooleanArray,
{
    fn add_padding_items<V: Extend<Self>, const B: usize>(
        direction_to_excluded_helper: Direction,
        padding_input_rows: &mut V,
        padding_params: &PaddingParameters,
        rng: &mut InstrumentedSequentialSharedRandomness,
    ) -> Result<u32, Error> {
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
                        let breakdownkey_shares = match direction_to_excluded_helper {
                            Direction::Left => AdditiveShare::new(
                                BK::ZERO,
                                BK::truncate_from(u128::from(breakdownkey)),
                            ),
                            Direction::Right => AdditiveShare::new(
                                BK::truncate_from(u128::from(breakdownkey)),
                                BK::ZERO,
                            ),
                        };

                        let row = AttributionOutputs {
                            attributed_breakdown_key_bits: breakdownkey_shares,
                            capped_attributed_trigger_value: AdditiveShare::new(TV::ZERO, TV::ZERO),
                        };

                        padding_input_rows.extend(std::iter::once(row));
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

            padding_input_rows.extend(std::iter::once(row));
        }
    }
}

/// # Errors
/// Will propagate errors from `apply_dp_padding_pass`
pub async fn apply_dp_padding<C, T, const B: usize>(
    ctx: C,
    mut input: Vec<T>,
    padding_params: PaddingParameters,
) -> Result<Vec<T>, Error>
where
    C: Context,
    T: Paddable,
{
    let initial_len = input.len();

    // H1 and H2 add padding noise
    input = apply_dp_padding_pass::<C, T, B>(
        ctx.narrow(&PaddingDpStep::PaddingDpPass1),
        input,
        Role::H3,
        &padding_params,
    )
    .await?;

    // H3 and H1 add padding noise
    input = apply_dp_padding_pass::<C, T, B>(
        ctx.narrow(&PaddingDpStep::PaddingDpPass2),
        input,
        Role::H2,
        &padding_params,
    )
    .await?;

    // H2 and H3 add padding noise
    input = apply_dp_padding_pass::<C, T, B>(
        ctx.narrow(&PaddingDpStep::PaddingDpPass3),
        input,
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
///     2.  `h_i` and `h_i_plus_one` will send the send `total_number_of_fake_rows` to `excluded_helper`
///     3.  `excluded_helper` will generate secret shares of zero for as many rows as the `total_number_of_fake_rows`
///
/// # Errors
/// Will propogate errors from `OPRFPaddingDp`. Will return an error if the two helpers adding noise
/// tell the excluded helper to add different numbers of fake rows.
/// # Panics
/// will panic if not able to fit the received value `v` into a `u32`
pub async fn apply_dp_padding_pass<C, T, const B: usize>(
    ctx: C,
    mut input: Vec<T>,
    excluded_helper: Role,
    padding_params: &PaddingParameters,
) -> Result<Vec<T>, Error>
where
    C: Context,
    T: Paddable,
{
    let total_number_of_fake_rows;
    let mut padding_input_rows: Vec<T> = Vec::new();
    let send_ctx = ctx
        .narrow(&SendTotalRows::SendNumFakeRecords)
        .set_total_records(TotalRecords::ONE);

    if let Some(direction_to_excluded_helper) = ctx.role().direction_to(excluded_helper) {
        // Step 1: Helpers `h_i` and `h_i_plus_one` will get the same rng from PRSS
        // and use it to sample the same random noise for padding from OPRFPaddingDp.
        // They will generate secret shares of these fake rows.
        let (mut left, mut right) = ctx.prss_rng();
        let rng = match direction_to_excluded_helper {
            Direction::Left => &mut right,
            Direction::Right => &mut left,
        };
        let total_number_of_fake_rows = T::add_padding_items::<Vec<T>, B>(
            direction_to_excluded_helper,
            &mut padding_input_rows,
            padding_params,
            rng,
        )?;

        // Step 2: `h_i` and `h_i_plus_one` will send the send `total_number_of_fake_rows` to the `excluded_helper`.
        // The `excluded_helper` will check that both `h_i` and `h_i_plus_one` have sent the same value
        // to prevent any malicious behavior. See oprf_padding/README.md for explanation of why revealing
        // the total number of fake rows is okay.
        let send_channel =
            send_ctx.send_channel::<BA32>(send_ctx.role().peer(direction_to_excluded_helper));
        send_channel
            .send(
                RecordId::FIRST,
                BA32::truncate_from(u128::from(total_number_of_fake_rows)),
            )
            .await?;
    } else {
        // Step 3: `h_out` will first receive the total_number_of_fake rows from the other
        // parties and then `h_out` will set its shares to zero for the fake rows
        let recv_channel_right =
            send_ctx.recv_channel::<BA32>(send_ctx.role().peer(Direction::Right));
        let recv_channel_left =
            send_ctx.recv_channel::<BA32>(send_ctx.role().peer(Direction::Left));
        // let (from_right, from_left) = try_join!(
        //     async {
        //         match recv_channel_right.receive(RecordId::FIRST).await {
        //             Ok(v) => Ok::<u32, Error>(u32::try_from(v.as_u128()).unwrap()),
        //             Err(e) => Err(e.into()),
        //         }
        //     },
        //     async {
        //         match recv_channel_left.receive(RecordId::FIRST).await {
        //             Ok(v) => Ok::<u32, Error>(u32::try_from(v.as_u128()).unwrap()),
        //             Err(e) => Err(e.into()),
        //         }
        //     }
        // )?;
        // if from_right != from_left {
        //     return Err::<Vec<T>, error::Error>(Error::InconsistentPadding);
        // }
        // total_number_of_fake_rows = from_right;

        let (from_right, from_left) = try_join!(
            recv_channel_right.receive(RecordId::FIRST),
            recv_channel_left.receive(RecordId::FIRST),
        )?;
        if from_right != from_left {
            return Err::<Vec<T>, error::Error>(Error::InconsistentPadding);
        }
        total_number_of_fake_rows = u32::try_from(from_right.as_u128()).unwrap();

        T::add_zero_shares(&mut padding_input_rows, total_number_of_fake_rows);
    }

    input.extend(padding_input_rows);
    Ok(input)
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
                prf_sharding::{tests::PreAggregationTestOutputInDecimal, AttributionOutputs},
                OPRFIPAInputRow,
            },
            RecordId,
        },
        secret_sharing::replicated::semi_honest::AdditiveShare,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    pub async fn set_up_apply_dp_padding_pass_for_oprf<C, BK, TV, TS, const B: usize>(
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
        input = apply_dp_padding_pass::<C, OPRFIPAInputRow<BK, TV, TS>, B>(
            ctx,
            input,
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
                set_up_apply_dp_padding_pass_for_oprf::<_, BK, TV, TS, B>(ctx, padding_params).await
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
        let tolerance_bound = 12.0;
        assert!(std_bound > 1.0); // bound on the std only holds if this is true.
        println!("mean = {mean}, std_bound = {std_bound}");
        for (sample, count) in &distribution_of_samples {
            println!("An OPRFPadding sample value equal to {sample} occurred {count} time(s)",);
            assert!(
                (f64::from(*sample) - mean).abs() < tolerance_bound * std_bound,
                "aggregation noise sample was not within {tolerance_bound} times the standard deviation bound from what was expected."
            );
        }
    }

    pub async fn set_up_apply_dp_padding_pass_for_agg<C, BK, TV, const B: usize>(
        ctx: C,
        padding_params: PaddingParameters,
    ) -> Result<Vec<AttributionOutputs<AdditiveShare<BK>, AdditiveShare<TV>>>, Error>
    where
        C: Context,
        BK: BooleanArray + U128Conversions,
        TV: BooleanArray,
    {
        let mut input: Vec<AttributionOutputs<AdditiveShare<BK>, AdditiveShare<TV>>> = Vec::new();
        input = apply_dp_padding_pass::<
            C,
            AttributionOutputs<AdditiveShare<BK>, AdditiveShare<TV>>,
            B,
        >(ctx, input, Role::H3, &padding_params)
        .await?;
        Ok(input)
    }

    #[tokio::test]
    pub async fn aggregation_noise_in_dp_padding_pass() {
        type BK = BA8;
        type TV = BA3;
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
                set_up_apply_dp_padding_pass_for_agg::<_, BK, TV, B>(ctx, padding_params).await
            })
            .await
            .map(Result::unwrap);

        // check that all three helpers added the same number of dummy shares
        assert!(result[0].len() == result[1].len() && result[0].len() == result[2].len());

        let result_reconstructed: Vec<PreAggregationTestOutputInDecimal> = result.reconstruct();

        let mut sample_per_breakdown: HashMap<u128, u32> = HashMap::new();
        for row in result_reconstructed {
            assert!(row.capped_attributed_trigger_value == 0);
            let sample = sample_per_breakdown
                .entry(row.attributed_breakdown_key)
                .or_insert(0);
            *sample += 1;
        }
        // check that all breakdowns had noise added
        assert!(B == sample_per_breakdown.len());

        let aggregation_padding = OPRFPaddingDp::new(
            aggregation_epsilon,
            aggregation_delta,
            aggregation_padding_sensitivity,
        )
        .unwrap();

        let (mean, std_bound) = aggregation_padding.mean_and_std_bound();
        assert!(std_bound > 1.0); // bound on the std only holds if this is true.
        let tolerance_factor = 12.0;
        println!(
            "mean = {mean}, std_bound = {std_bound}, {tolerance_factor} * std_bound = {}",
            tolerance_factor * std_bound
        );
        for sample in sample_per_breakdown.values() {
            assert!(
                (f64::from(*sample) - mean).abs() < tolerance_factor * std_bound,
                "aggregation noise sample = {} was not within {tolerance_factor} times the standard deviation bound \
                ({tolerance_factor} * std_bound = {}) from what was expected (mean = {mean}). For Laplace this will fail ~ 0.03% of the time randomly.",
                *sample,
                tolerance_factor * std_bound,
            );
        }
    }

    /// ////////////////////////////////////////////////////////////////////////////////////
    /// Analysis of Parameters
    ///
    ///
    ///
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
    #[ignore]
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
                    let aggregation_padding_sensitivity = matchkey_cardinality_cap; // TODO not necessary to have this
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

    /// ///////////////////////////////////////////////////////////////////
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
