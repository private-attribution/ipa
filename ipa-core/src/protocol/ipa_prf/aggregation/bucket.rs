use std::iter::repeat;

use embed_doc_image::embed_doc_image;
use ipa_macros::Step;

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{
        basics::SecureMul, context::Context, ipa_prf::prf_sharding::BinaryTreeDepthStep,
        step::BitOpStep, RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd},
};

#[derive(Step)]
pub enum BucketStep {
    #[dynamic(256)]
    Bit(usize),
}

impl TryFrom<u32> for BucketStep {
    type Error = String;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        let val = usize::try_from(v);
        let val = match val {
            Ok(val) => Self::Bit(val),
            Err(error) => panic!("{error:?}"),
        };
        Ok(val)
    }
}

impl From<usize> for BucketStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

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
    const MAX_BREAKDOWNS: usize = 512; // constrained by the compact step ability to generate dynamic steps
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

    for (tree_depth, bit_of_bdkey) in bd_key.iter().enumerate().rev() {
        let span = step >> 1;
        if !robust && span > breakdown_count {
            step = span;
            continue;
        }

        let depth_c = ctx.narrow(&BinaryTreeDepthStep::from(tree_depth));
        let mut futures = Vec::with_capacity(breakdown_count / step);

        for (i, tree_index) in (0..breakdown_count).step_by(step).enumerate() {
            let bucket_c = depth_c.narrow(&BucketStep::from(i));

            let index_contribution = row_contribution[tree_index].iter();

            if robust || tree_index + span < breakdown_count {
                futures.push(async move {
                    let bit_futures = index_contribution
                        .zip(repeat((bit_of_bdkey, bucket_c.clone())))
                        .enumerate()
                        .map(|(i, (a, (b, bucket_c)))| {
                            a.multiply(b, bucket_c.narrow(&BitOpStep::Bit(i)), record_id)
                        });
                    BitDecomposed::try_from(bucket_c.parallel_join(bit_futures).await?)
                });
            }
        }
        let contributions = ctx.parallel_join(futures).await?;

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
