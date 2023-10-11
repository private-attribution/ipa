use futures::{Stream, TryStreamExt};

use crate::{
    error::Error,
    helpers::{
        query::{oprf_shuffle, QuerySize},
        BodyStream, RecordsStream,
    },
    protocol::{
        context::Context,
        oprf::{oprf_shuffle, OPRFInputRow},
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
    ) -> Result<Vec<OPRFInputRow>, Error> {
        let input: Vec<OPRFInputRow> =
            assert_stream_send(RecordsStream::<OPRFInputRow, _>::new(input_stream))
                .try_concat()
                .await?;

        oprf_shuffle(ctx, input.as_slice(), self.config).await
    }
}

/// Helps to convince the compiler that things are `Send`. Like `seq_join::assert_send`, but for
/// streams.
///
/// <https://github.com/rust-lang/rust/issues/102211#issuecomment-1367900125>
pub fn assert_stream_send<'a, T>(
    st: impl Stream<Item = T> + Send + 'a,
) -> impl Stream<Item = T> + Send + 'a {
    st
}
