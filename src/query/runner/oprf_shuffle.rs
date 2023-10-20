use futures::TryStreamExt;

use crate::{
    error::Error,
    helpers::{
        query::{oprf_shuffle, QuerySize},
        BodyStream, RecordsStream,
    },
    one_off_fns::assert_stream_send,
    protocol::{
        context::Context,
        oprf::shuffle::{shuffle, ShuffleInputRow},
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

        shuffle(ctx, input.as_slice(), self.config).await
    }
}
