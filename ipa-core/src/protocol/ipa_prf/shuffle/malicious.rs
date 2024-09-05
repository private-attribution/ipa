use futures::stream::StreamExt;
use futures_util::stream::iter;

use crate::{
    error::Error,
    ff::{boolean_array::BooleanArray, Gf32Bit},
    helpers::TotalRecords,
    protocol::{basics::mul::semi_honest_multiply, context::Context, RecordId},
    secret_sharing::replicated::semi_honest::AdditiveShare,
    seq_join::seq_join,
};

async fn compute_tags<C: Context, S: BooleanArray>(
    ctx: C,
    keys: &[AdditiveShare<Gf32Bit>],
    rows: &[AdditiveShare<S>],
) -> Result<Vec<AdditiveShare<Gf32Bit>>, Error> {
    let length = rows.len();
    let row_length = keys.len();
    let tag_ctx = ctx.set_total_records(TotalRecords::specified(length * row_length)?);
    let p_ctx = &tag_ctx;

    let futures = rows.iter().enumerate().map(|(i, row)| async move {
        let row_entries: Vec<AdditiveShare<Gf32Bit>> = row.try_into().unwrap();
        let a = p_ctx
            .parallel_join(row_entries.iter().zip(keys).enumerate().map(
                |(j, (row_entry, key))| async move {
                    semi_honest_multiply(
                        p_ctx.clone(),
                        RecordId::from(i * row_length + j),
                        row_entry,
                        key,
                    )
                    .await
                },
            ))
            .await
            .unwrap()
            .iter()
            .fold(AdditiveShare::<Gf32Bit>::ZERO, |acc, x| acc + x);
        a
    });

    Ok(seq_join(ctx.active_work(), iter(futures))
        .collect::<Vec<_>>()
        .await)
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;
    use crate::{
        ff::boolean_array::{BA32, BA64},
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[test]
    fn check_tags_single_row() {
        const RECORD_AMOUNT: usize = 10;
        run(|| async {
            let world = TestWorld::default();
            let mut rng = thread_rng();
            let records = (0..RECORD_AMOUNT)
                .map(|_| rng.gen::<BA32>())
                .collect::<Vec<_>>();
            let key = rng.gen::<BA32>();

            let converted_key: Vec<Gf32Bit> = key.try_into().unwrap();

            let expected_tags = records
                .iter()
                .map(|&record| {
                    <BA32 as TryInto<Vec<Gf32Bit>>>::try_into(record).unwrap()[0] * converted_key[0]
                })
                .collect::<Vec<Gf32Bit>>();

            let tags = world
                .semi_honest(
                    (records.into_iter(), key),
                    |ctx, (row_shares, key_shares)| async move {
                        // convert key
                        let mac_key: Vec<AdditiveShare<Gf32Bit>> =
                            (&key_shares).try_into().unwrap();
                        compute_tags(ctx, &mac_key, &row_shares).await.unwrap()
                    },
                )
                .await
                .reconstruct();

            assert_eq!(tags, expected_tags);
        });
    }

    #[test]
    fn check_tags_two_rows() {
        const RECORD_AMOUNT: usize = 10;
        run(|| async {
            let world = TestWorld::default();
            let mut rng = thread_rng();
            let records = (0..RECORD_AMOUNT)
                .map(|_| rng.gen::<BA64>())
                .collect::<Vec<_>>();
            let keys = rng.gen::<BA64>();

            let converted_keys: Vec<Gf32Bit> = keys.try_into().unwrap();

            let expected_tags = records
                .iter()
                .map(|&record| {
                    let converted_record: Vec<Gf32Bit> = record.try_into().unwrap();
                    converted_record[0] * converted_keys[0]
                        + (converted_record[1] * converted_keys[1])
                })
                .collect::<Vec<Gf32Bit>>();

            let tags = world
                .semi_honest(
                    (records.into_iter(), keys),
                    |ctx, (row_shares, key_shares)| async move {
                        // convert key
                        let mac_key: Vec<AdditiveShare<Gf32Bit>> =
                            (&key_shares).try_into().unwrap();
                        compute_tags(ctx, &mac_key, &row_shares).await.unwrap()
                    },
                )
                .await
                .reconstruct();

            assert_eq!(tags, expected_tags);
        });
    }
}
