use futures::TryStreamExt;

use super::{share::ShuffleShare, ShuffleInputRow};
use crate::{
    assert_stream_send,
    error::Error,
    helpers::{
        query::{oprf_shuffle, QuerySize},
        BodyStream, Direction, RecordsStream,
    },
    protocol::{context::Context, oprf::shuffle::shuffle},
    secret_sharing::replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
};

pub struct OPRFShuffleQuery {
    _config: oprf_shuffle::QueryConfig,
}

impl OPRFShuffleQuery {
    pub fn new(config: oprf_shuffle::QueryConfig) -> Self {
        Self { _config: config }
    }

    #[tracing::instrument("shuffle_query", skip_all, fields(sz=%query_size))]
    pub async fn execute<'a, C: Context + Send>(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<ShuffleInputRow>, Error> {
        let mut input: Vec<ShuffleInputRow> =
            assert_stream_send(RecordsStream::<ShuffleInputRow, _>::new(input_stream))
                .try_concat()
                .await?;
        input.truncate(usize::from(query_size));

        let batch_size = input.len();
        let shares = split_shares(&input);
        let res = shuffle(ctx, batch_size, shares).await?;
        Ok(combine_shares(res.iter()))
    }
}

fn split_shares(
    input_rows: &[ShuffleInputRow],
) -> impl Iterator<Item = AdditiveShare<ShuffleShare>> + '_ {
    let f = move |input_row| {
        let l = from_input_row(input_row, Direction::Left);
        let r = from_input_row(input_row, Direction::Right);
        ReplicatedSecretSharing::new(l, r)
    };

    input_rows.iter().map(f)
}

fn combine_shares<'a>(
    input: impl IntoIterator<Item = &'a AdditiveShare<ShuffleShare>>,
) -> Vec<ShuffleInputRow> {
    input.into_iter().map(to_input_row).collect::<Vec<_>>()
}

fn from_input_row(input_row: &ShuffleInputRow, shared_with: Direction) -> ShuffleShare {
    match shared_with {
        Direction::Left => ShuffleShare {
            timestamp: input_row.timestamp.as_tuple().1,
            mk: input_row.mk_shares.as_tuple().1,
            is_trigger_bit: input_row.is_trigger_bit.as_tuple().1,
            breakdown_key: input_row.breakdown_key.as_tuple().1,
            trigger_value: input_row.trigger_value.as_tuple().1,
        },

        Direction::Right => ShuffleShare {
            timestamp: input_row.timestamp.as_tuple().0,
            mk: input_row.mk_shares.as_tuple().0,
            is_trigger_bit: input_row.is_trigger_bit.as_tuple().0,
            breakdown_key: input_row.breakdown_key.as_tuple().0,
            trigger_value: input_row.trigger_value.as_tuple().0,
        },
    }
}

fn to_input_row(input: &AdditiveShare<ShuffleShare>) -> ShuffleInputRow {
    ShuffleInputRow {
        timestamp: ReplicatedSecretSharing::map(input, |v| v.timestamp),
        mk_shares: ReplicatedSecretSharing::map(input, |v| v.mk),
        is_trigger_bit: ReplicatedSecretSharing::map(input, |v| v.is_trigger_bit),
        breakdown_key: ReplicatedSecretSharing::map(input, |v| v.breakdown_key),
        trigger_value: ReplicatedSecretSharing::map(input, |v| v.trigger_value),
    }
}
