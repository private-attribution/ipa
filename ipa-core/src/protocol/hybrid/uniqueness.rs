use futures::{stream::iter, TryFutureExt, TryStreamExt};

use crate::{
    error::Error,
    helpers::stream::FixedLength,
    protocol::context::{reshard_stream, ShardedContext},
    report::hybrid::{UniqueBytes, UniqueTag, UniqueTagValidator},
};

pub async fn verify_uniqueness<K, C>(
    ctx: C,
    input: Vec<K>,
    input_sz: usize,
    mut unique_tag_validator: UniqueTagValidator,
) -> impl TryStreamExt<Item = Result<(), Error>>
where
    K: UniqueBytes,
    C: ShardedContext,
{
    let tags = iter(
        input
            .into_iter()
            .map(|i| UniqueTag::from_unique_bytes(&i))
            .collect::<Vec<_>>(),
    );

    let fixed_length_tags = FixedLength::new(tags, input_sz);

    reshard_stream(ctx, fixed_length_tags, |ctx, _, tag: &UniqueTag| {
        tag.shard_picker(ctx.shard_count())
    })
    .map_err(Into::<Error>::into)
    .map_ok(|resharded_tags| unique_tag_validator.check_duplicates(&resharded_tags))
}
