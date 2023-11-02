use embed_doc_image::embed_doc_image;
use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{GaloisField, PrimeField, Serializable},
    protocol::{
        basics::SecureMul, context::UpgradedContext, ipa_prf::prf_sharding::BinaryTreeDepthStep,
        RecordId,
    },
    secret_sharing::{
        replicated::malicious::ExtendableField, BitDecomposed, Linear as LinearSecretSharing,
    },
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
pub async fn move_single_value_to_bucket<BK, C, S, F>(
    ctx: C,
    record_id: RecordId,
    bd_key: BitDecomposed<S>,
    value: S,
    breakdown_count: usize,
    robust: bool,
) -> Result<Vec<S>, Error>
where
    BK: GaloisField,
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + Serializable + SecureMul<C>,
    F: PrimeField + ExtendableField,
{
    let mut step: usize = 1 << BK::BITS;

    assert!(
        breakdown_count <= 1 << BK::BITS,
        "Asking for more buckets ({breakdown_count}) than bits in the key ({}) allow",
        BK::BITS
    );
    assert!(
        breakdown_count <= 512,
        "Our step implementation (BucketStep) cannot go past 256"
    );
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
            let bit_c = depth_c.narrow(&BucketStep::from(i));

            if robust || tree_index + span < breakdown_count {
                futures.push(row_contribution[tree_index].multiply(bit_of_bdkey, bit_c, record_id));
            }
        }
        let contributions = ctx.parallel_join(futures).await?;

        for (index, bdbit_contribution) in contributions.into_iter().enumerate() {
            let left_index = index * step;
            let right_index = left_index + span;

            row_contribution[left_index] -= &bdbit_contribution;
            if right_index < breakdown_count {
                row_contribution[right_index] = bdbit_contribution;
            }
        }
        step = span;
    }
    Ok(row_contribution)
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use rand::thread_rng;

    use crate::{
        ff::{Field, Fp32BitPrime, Gf8Bit, Gf9Bit},
        protocol::{
            context::{Context, UpgradableContext, Validator},
            ipa_prf::prf_sharding::bucket::move_single_value_to_bucket,
            RecordId,
        },
        rand::Rng,
        secret_sharing::SharedValue,
        test_executor::run,
        test_fixture::{get_bits, Reconstruct, Runner, TestWorld},
    };

    const MAX_BREAKDOWN_COUNT: usize = 256;
    const VALUE: u32 = 10;

    async fn move_to_bucket(count: usize, breakdown_key: usize, robust: bool) -> Vec<Fp32BitPrime> {
        let breakdown_key_bits =
            get_bits::<Fp32BitPrime>(breakdown_key.try_into().unwrap(), Gf8Bit::BITS);
        let value = Fp32BitPrime::truncate_from(VALUE);

        TestWorld::default()
            .semi_honest(
                (breakdown_key_bits, value),
                |ctx, (breakdown_key_share, value_share)| async move {
                    let validator = ctx.validator();
                    let ctx = validator.context();
                    move_single_value_to_bucket::<Gf8Bit, _, _, Fp32BitPrime>(
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
    }

    #[test]
    fn semi_honest_move_in_range() {
        run(|| async move {
            let mut rng = thread_rng();
            let count = rng.gen_range(1..MAX_BREAKDOWN_COUNT);
            let breakdown_key = rng.gen_range(0..count);
            let mut expected = vec![Fp32BitPrime::ZERO; count];
            expected[breakdown_key] = Fp32BitPrime::truncate_from(VALUE);

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
            let mut expected = vec![Fp32BitPrime::ZERO; count];
            expected[breakdown_key] = Fp32BitPrime::truncate_from(VALUE);

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
                result.into_iter().sum::<Fp32BitPrime>(),
                Fp32BitPrime::truncate_from(VALUE)
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
            assert!(result.into_iter().all(|x| x == Fp32BitPrime::ZERO));
        });
    }

    #[test]
    #[should_panic]
    fn move_out_of_range_too_many_buckets_type() {
        run(move || async move {
            _ = move_to_bucket(MAX_BREAKDOWN_COUNT + 1, 0, false).await;
        });
    }

    #[test]
    #[should_panic]
    fn move_out_of_range_too_many_buckets_steps() {
        run(move || async move {
            let breakdown_key_bits = get_bits::<Fp32BitPrime>(0, Gf9Bit::BITS);
            let value = Fp32BitPrime::truncate_from(VALUE);

            _ = TestWorld::default()
                .semi_honest(
                    (breakdown_key_bits, value),
                    |ctx, (breakdown_key_share, value_share)| async move {
                        let validator = ctx.validator();
                        let ctx = validator.context();
                        move_single_value_to_bucket::<Gf9Bit, _, _, Fp32BitPrime>(
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
