use futures::TryStreamExt;

use crate::{
    error::Error,
    helpers::{
        query::{oprf_shuffle, QuerySize},
        BodyStream, Direction, RecordsStream,
    },
    one_off_fns::assert_stream_send,
    protocol::{
        context::Context,
        oprf::shuffle::{share::ShuffleShare, shuffle, ShuffleInputRow},
    },
};

pub struct OPRFShuffleQuery {
    config: oprf_shuffle::QueryConfig,
}

impl OPRFShuffleQuery {
    pub fn new(config: oprf_shuffle::QueryConfig) -> Self {
        Self { config }
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

        let batch_size = u32::try_from(input.len()).map_err(|_e| {
            Error::FieldValueTruncation(format!(
                "Cannot truncate the number of input rows {} to u32",
                input.len(),
            ))
        })?;

        let shares = (
            split_shares(input.as_slice(), Direction::Left),
            split_shares(input.as_slice(), Direction::Right),
        );

        let (res_l, res_r) = shuffle(self.config, ctx, batch_size, shares).await?;
        Ok(combine_shares(res_l, res_r))
    }
}

fn split_shares(
    input_rows: &[ShuffleInputRow],
    direction: Direction,
) -> impl Iterator<Item = ShuffleShare> + '_ {
    let f = move |input_row| ShuffleShare::from_input_row(input_row, direction);
    input_rows.iter().map(f)
}

fn combine_shares<L, R>(l: L, r: R) -> Vec<ShuffleInputRow>
where
    L: IntoIterator<Item = ShuffleShare>,
    R: IntoIterator<Item = ShuffleShare>,
{
    l.into_iter()
        .zip(r)
        .map(|(l, r)| l.to_input_row(r))
        .collect::<Vec<_>>()
}
