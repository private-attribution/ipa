use embed_doc_image::embed_doc_image;

use crate::{
    error::Error,
    ff::boolean::Boolean,
    helpers::repeat_n,
    protocol::{
        basics::SecureMul, boolean::and::bool_and_8_bit, context::Context,
        ipa_prf::aggregation::step::BucketStep, RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd},
};

const MAX_BREAKDOWNS: usize = 512; // constrained by the compact step ability to generate dynamic steps

#[derive(thiserror::Error, Debug)]
pub enum MoveToBucketError {
    #[error("Bad value for the breakdown key: {0}")]
    InvalidBreakdownKey(String),
}

impl From<MoveToBucketError> for Error {
    fn from(error: MoveToBucketError) -> Self {
        match error {
            e @ MoveToBucketError::InvalidBreakdownKey(_) => {
                Error::InvalidQueryParameter(Box::new(e))
            }
        }
    }
}

#[embed_doc_image("tree-aggregation", "images/tree_aggregation.png")]
/// This function moves a single value to a correct bucket using tree aggregation approach
///
/// Here is how it works
/// The combined value,  [`value`] forms the root of a binary tree as follows:
/// ![Tree propagation][tree-aggregation]
///
/// This value is propagated through the tree, with each subsequent iteration doubling the number of multiplications.
/// In the first round,  r=BK-1, multiply the most significant bit ,[`bd_key`]_r by the value to get [`bd_key`]_r.[`value`]. From that,
/// produce [`row_contribution`]_r,0 =[`value`]-[`bd_key`]_r.[`value`] and [`row_contribution`]_r,1=[`bd_key`]_r.[`value`].
/// This takes the most significant bit of `bd_key` and places value in one of the two child nodes of the binary tree.
/// At each successive round, the next most significant bit is propagated from the leaf nodes of the tree into further leaf nodes:
/// [`row_contribution`]_r+1,q,0 =[`row_contribution`]_r,q - [`bd_key`]_r+1.[`row_contribution`]_r,q and [`row_contribution`]_r+1,q,1 =[`bd_key`]_r+1.[`row_contribution`]_r,q.
/// The work of each iteration therefore doubles relative to the one preceding.
///
/// In case a malicious entity sends a out of range breakdown key (i.e. greater than the max count) to this function, we need to do some
/// extra processing to ensure contribution doesn't end up in a wrong bucket. However, this requires extra multiplications.
/// This would potentially not be needed in IPA (as the breakdown key is provided by the report collector, so a bad value only spoils their own result) but useful for PAM.
/// This can be by passing `robust` as true.
///
/// ## Errors
/// If `breakdown_count` does not fit into `BK` bits or greater than or equal to $2^9$
#[allow(dead_code)]
pub async fn move_single_value_to_bucket<C, const N: usize>(
    ctx: C,
    record_id: RecordId,
    bd_key: BitDecomposed<AdditiveShare<Boolean, N>>,
    value: BitDecomposed<AdditiveShare<Boolean, N>>,
    breakdown_count: usize,
    robust: bool,
) -> Result<Vec<BitDecomposed<AdditiveShare<Boolean, N>>>, Error>
where
    C: Context,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: SecureMul<C>,
{
    let mut step: usize = 1 << bd_key.len();

    if breakdown_count > step {
        Err(MoveToBucketError::InvalidBreakdownKey(format!(
            "Asking for more buckets ({breakdown_count}) than bits in the breakdown key ({}) allow",
            bd_key.len()
        )))?;
    }

    if breakdown_count > MAX_BREAKDOWNS {
        Err(MoveToBucketError::InvalidBreakdownKey(
            "Our step implementation (BucketStep) cannot go past {MAX_BREAKDOWNS} breakdown keys"
                .to_string(),
        ))?;
    }

    let mut row_contribution = vec![value; breakdown_count];

    // To move a value to one of 2^bd_key_bits buckets requires 2^bd_key_bits - 1 multiplications
    // They happen in a tree like fashion:
    // 1 multiplication for the first bit
    // 2 for the second bit
    // 4 for the 3rd bit
    // And so on. Simply ordering them sequentially is a functional way
    // of enumerating them without creating more step transitions than necessary
    let mut multiplication_channel = 0;

    for bit_of_bdkey in bd_key.iter().rev() {
        let span = step >> 1;
        if !robust && span > breakdown_count {
            step = span;
            continue;
        }

        let contributions = ctx
            .parallel_join((0..breakdown_count).step_by(step).enumerate().filter_map(
                |(i, tree_index)| {
                    let bucket_c = ctx.narrow(&BucketStep::from(multiplication_channel + i));

                    let index_contribution = &row_contribution[tree_index];

                    (robust || tree_index + span < breakdown_count).then(|| {
                        bool_and_8_bit(
                            bucket_c,
                            record_id,
                            index_contribution,
                            repeat_n(bit_of_bdkey, index_contribution.len()),
                        )
                    })
                },
            ))
            .await?;
        multiplication_channel += contributions.len();

        for (index, bdbit_contribution) in contributions.into_iter().enumerate() {
            let left_index = index * step;
            let right_index = left_index + span;

            // bdbit_contribution is either zero or equal to row_contribution. So it
            // is okay to do a carryless "subtraction" here.
            for (r, b) in row_contribution[left_index]
                .iter_mut()
                .zip(bdbit_contribution.iter())
            {
                *r -= b;
            }
            if right_index < breakdown_count {
                for (r, b) in row_contribution[right_index]
                    .iter_mut()
                    .zip(bdbit_contribution)
                {
                    *r = b;
                }
            }
        }
        step = span;
    }
    Ok(row_contribution)
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use rand::thread_rng;

    use super::move_single_value_to_bucket;
    use crate::{
        ff::{boolean::Boolean, boolean_array::BA8, Gf8Bit, Gf9Bit, U128Conversions},
        protocol::{context::Context, RecordId},
        rand::Rng,
        secret_sharing::{BitDecomposed, SharedValue},
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    const MAX_BREAKDOWN_COUNT: usize = 256;
    const VALUE: u32 = 10;

    async fn move_to_bucket(count: usize, breakdown_key: usize, robust: bool) -> Vec<BA8> {
        let breakdown_key_bits = BitDecomposed::decompose(Gf8Bit::BITS, |i| {
            Boolean::from((breakdown_key >> i) & 1 == 1)
        });
        let value =
            BitDecomposed::decompose(Gf8Bit::BITS, |i| Boolean::from((VALUE >> i) & 1 == 1));

        TestWorld::default()
            .semi_honest(
                (breakdown_key_bits, value),
                |ctx, (breakdown_key_share, value_share)| async move {
                    move_single_value_to_bucket::<_, 1>(
                        ctx.set_total_records(1),
                        RecordId::from(0),
                        breakdown_key_share,
                        value_share,
                        count,
                        robust,
                    )
                    .await
                    .unwrap()
                },
            )
            .await
            .reconstruct()
            .into_iter()
            .map(|val| val.into_iter().collect())
            .collect()
    }

    #[test]
    fn semi_honest_move_in_range() {
        run(|| async move {
            let mut rng = thread_rng();
            let count = rng.gen_range(1..MAX_BREAKDOWN_COUNT);
            let breakdown_key = rng.gen_range(0..count);
            let mut expected = vec![BA8::ZERO; count];
            expected[breakdown_key] = BA8::truncate_from(VALUE);

            let result = move_to_bucket(count, breakdown_key, false).await;
            assert_eq!(result, expected, "expected value at index {breakdown_key}");
        });
    }

    #[test]
    fn semi_honest_move_in_range_robust() {
        run(|| async move {
            let mut rng = thread_rng();
            let count = rng.gen_range(1..MAX_BREAKDOWN_COUNT);
            let breakdown_key = rng.gen_range(0..count);
            let mut expected = vec![BA8::ZERO; count];
            expected[breakdown_key] = BA8::truncate_from(VALUE);

            let result = move_to_bucket(count, breakdown_key, true).await;
            assert_eq!(result, expected, "expected value at index {breakdown_key}");
        });
    }

    #[test]
    fn semi_honest_move_out_of_range() {
        run(move || async move {
            let mut rng: rand::rngs::ThreadRng = thread_rng();
            let count = rng.gen_range(2..MAX_BREAKDOWN_COUNT - 1);
            let breakdown_key = rng.gen_range(count..MAX_BREAKDOWN_COUNT);

            let result = move_to_bucket(count, breakdown_key, false).await;
            assert_eq!(result.len(), count);
            assert_eq!(
                result.into_iter().fold(0, |acc, v| acc + v.as_u128()),
                u128::from(VALUE)
            );
        });
    }

    #[test]
    fn semi_honest_move_out_of_range_robust() {
        run(move || async move {
            let mut rng: rand::rngs::ThreadRng = thread_rng();
            let count = rng.gen_range(2..MAX_BREAKDOWN_COUNT - 1);
            let breakdown_key = rng.gen_range(count..MAX_BREAKDOWN_COUNT);

            let result = move_to_bucket(count, breakdown_key, true).await;
            assert_eq!(result.len(), count);
            assert!(result.into_iter().all(|x| x == BA8::ZERO));
        });
    }

    #[test]
    #[should_panic(expected = "Asking for more buckets")]
    fn move_out_of_range_too_many_buckets_type() {
        run(move || async move {
            _ = move_to_bucket(MAX_BREAKDOWN_COUNT + 1, 0, false).await;
        });
    }

    #[test]
    #[should_panic(expected = "Asking for more buckets")]
    fn move_out_of_range_too_many_buckets_steps() {
        run(move || async move {
            let breakdown_key_bits = BitDecomposed::decompose(Gf9Bit::BITS, |_| Boolean::FALSE);
            let value =
                BitDecomposed::decompose(Gf8Bit::BITS, |i| Boolean::from((VALUE >> i) & 1 == 1));

            _ = TestWorld::default()
                .semi_honest(
                    (breakdown_key_bits, value),
                    |ctx, (breakdown_key_share, value_share)| async move {
                        move_single_value_to_bucket::<_, 1>(
                            ctx.set_total_records(1),
                            RecordId::from(0),
                            breakdown_key_share,
                            value_share,
                            513,
                            false,
                        )
                        .await
                        .unwrap()
                    },
                )
                .await;
        });
    }
}
