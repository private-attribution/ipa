use futures::TryStreamExt;

use super::{share::ShuffleShare, ShuffleInputRow};
use crate::{
    error::Error,
    helpers::{
        query::{oprf_shuffle, QuerySize},
        BodyStream, Direction, RecordsStream,
    },
    one_off_fns::assert_stream_send,
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

    #[tracing::instrument("ipa_query", skip_all, fields(sz=%query_size))]
    pub async fn execute<'a, C: Context + Send>(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<ShuffleInputRow>, Error> {
        let input: Vec<ShuffleInputRow> =
            assert_stream_send(RecordsStream::<ShuffleInputRow, _>::new(input_stream))
                .try_concat()
                .await?;

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
        let l = ShuffleShare::from_input_row(input_row, Direction::Left);
        let r = ShuffleShare::from_input_row(input_row, Direction::Right);
        ReplicatedSecretSharing::new(l, r)
    };

    input_rows.iter().map(f)
}

fn combine_shares<'a>(
    input: impl IntoIterator<Item = &'a AdditiveShare<ShuffleShare>>,
) -> Vec<ShuffleInputRow> {
    input
        .into_iter()
        .map(ShuffleShare::to_input_row)
        .collect::<Vec<_>>()
}
