use futures::stream::StreamExt;
use futures_util::stream::iter;
use generic_array::GenericArray;

use crate::{
    error::Error,
    ff::{boolean_array::BooleanArray, Gf32Bit, Serializable},
    helpers::TotalRecords,
    protocol::{basics::mul::semi_honest_multiply, context::Context, RecordId},
    secret_sharing::replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
    seq_join::seq_join,
};

/// This function computes the MAC tags and appends them to the rows.
/// The vector of rows concatenated with the tags is then output.
///
/// ## Error
/// Propagates MPC multiplication errors.
///
/// ## Panics
/// When conversion fails or when `S::Bits + 32 != B::Bits`.
async fn compute_and_add_tags<C: Context, S: BooleanArray, B: BooleanArray>(
    ctx: C,
    keys: &[AdditiveShare<Gf32Bit>],
    rows: &[AdditiveShare<S>],
) -> Result<Vec<AdditiveShare<B>>, Error> {
    let length = rows.len();
    let row_length = keys.len();
    let tag_ctx = ctx.set_total_records(TotalRecords::specified(length * row_length)?);
    let p_ctx = &tag_ctx;

    let futures = rows.iter().enumerate().map(|(i, row)| async move {
        let row_entries: Vec<AdditiveShare<Gf32Bit>> = row.try_into().unwrap();
        // compute tags via inner product between row and keys
        let row_tag = p_ctx
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
        // combine row and row_tag
        concatenate_row_and_tag::<S, B>(row, &row_tag)
    });

    Ok(seq_join(ctx.active_work(), iter(futures))
        .collect::<Vec<_>>()
        .await)
}

/// This helper function concatenates `row` and `row_tag`
///
/// ## Panics
/// Panics when `S::Bits +32 != B::Bits`.
fn concatenate_row_and_tag<S: BooleanArray, B: BooleanArray>(
    row: &AdditiveShare<S>,
    tag: &AdditiveShare<Gf32Bit>,
) -> AdditiveShare<B> {
    let mut row_left = GenericArray::default();
    let mut row_right = GenericArray::default();
    let mut tag_left = GenericArray::default();
    let mut tag_right = GenericArray::default();
    row.left().serialize(&mut row_left);
    row.right().serialize(&mut row_right);
    tag.left().serialize(&mut tag_left);
    tag.right().serialize(&mut tag_right);
    AdditiveShare::new(
        B::deserialize(&row_left.into_iter().chain(tag_left).collect()).unwrap(),
        B::deserialize(&row_right.into_iter().chain(tag_right).collect()).unwrap(),
    )
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::{distributions::Standard, prelude::Distribution, thread_rng, Rng};

    use super::*;
    use crate::{
        ff::boolean_array::{BA112, BA144, BA32, BA64},
        secret_sharing::SharedValue,
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    /// Helper function for tests below.
    /// `S::Bits + 32` needs to be the same as `B::Bits`
    fn check_concatenate<S, B>()
    where
        S: BooleanArray,
        B: BooleanArray,
        Standard: Distribution<S>,
    {
        let mut rng = thread_rng();
        let row = AdditiveShare::<S>::new(rng.gen(), rng.gen());
        let tag = AdditiveShare::<Gf32Bit>::new(rng.gen::<Gf32Bit>(), rng.gen::<Gf32Bit>());
        let row_and_tag: AdditiveShare<B> = concatenate_row_and_tag(&row, &tag);

        let mut buf = GenericArray::default();
        let mut buf_row = GenericArray::default();
        let mut buf_tag = GenericArray::default();

        let offset = usize::try_from((S::BITS + 7) / 8).unwrap();

        // check left
        row_and_tag.left().serialize(&mut buf);
        row.left().serialize(&mut buf_row);
        assert_eq!(buf[0..offset], buf_row[..]);
        tag.left().serialize(&mut buf_tag);
        assert_eq!(buf[offset..], buf_tag[..]);

        // check right
        row_and_tag.right().serialize(&mut buf);
        row.right().serialize(&mut buf_row);
        assert_eq!(buf[0..offset], buf_row[..]);
        tag.right().serialize(&mut buf_tag);
        assert_eq!(buf[offset..], buf_tag[..]);
    }

    #[test]
    fn check_concatenate_for_boolean_arrays() {
        check_concatenate::<BA32, BA64>();
        check_concatenate::<BA112, BA144>();
    }

    /// Helper function for checking the tags
    /// `S::Bits + 32` needs to be the same as `B::Bits`
    fn check_tags<S, B>()
    where
        S: BooleanArray,
        B: BooleanArray,
        Standard: Distribution<S>,
    {
        const RECORD_AMOUNT: usize = 10;
        run(|| async {
            let world = TestWorld::default();
            let mut rng = thread_rng();
            let records = (0..RECORD_AMOUNT)
                .map(|_| rng.gen::<S>())
                .collect::<Vec<_>>();
            // last key is not uniform but that is ok for test
            let keys = rng.gen::<S>();

            let converted_keys: Vec<Gf32Bit> = keys.try_into().unwrap();

            let expected_tags = records
                .iter()
                .map(|&record| {
                    let converted_record: Vec<Gf32Bit> = record.try_into().unwrap();
                    converted_record
                        .into_iter()
                        .zip(converted_keys.iter())
                        .fold(Gf32Bit::ZERO, |acc, (row_entry, &key)| {
                            acc + row_entry * key
                        })
                })
                .collect::<Vec<Gf32Bit>>();

            let rows_and_tags: Vec<B> = world
                .semi_honest(
                    (records.into_iter(), keys),
                    |ctx, (row_shares, key_shares)| async move {
                        // convert key
                        let mac_key: Vec<AdditiveShare<Gf32Bit>> =
                            (&key_shares).try_into().unwrap();
                        compute_and_add_tags(ctx, &mac_key, &row_shares)
                            .await
                            .unwrap()
                    },
                )
                .await
                .reconstruct();

            let offset = usize::try_from((B::BITS + 7) / 8).unwrap() - 4;
            // conversion
            let tags: Vec<Gf32Bit> = rows_and_tags
                .into_iter()
                .map(|x| {
                    let mut buf = GenericArray::default();
                    x.serialize(&mut buf);
                    <Gf32Bit>::deserialize(GenericArray::from_slice(&buf.as_slice()[offset..]))
                        .unwrap()
                })
                .collect();

            assert_eq!(tags, expected_tags);
        });
    }

    #[test]
    fn check_tags_for_boolean_arrays() {
        check_tags::<BA32, BA64>();
        check_tags::<BA112, BA144>();
    }
}
