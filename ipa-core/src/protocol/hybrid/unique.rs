use std::{error::Error, ops::Deref};

use crate::{
    protocol::context::{reshard, ShardedContext, UpgradableContext},
    report::ipa::EncryptedOprfReport,
    secret_sharing::SharedValue,
    seq_join::assert_send,
};

#[derive(Clone)]
struct IndexedEncryptedOprfReport<'a, BK, V, TS, B>
where
    B: Deref<Target = [u8]>,
    BK: SharedValue,
    V: SharedValue,
    TS: SharedValue,
{
    index: usize,
    report: &'a EncryptedOprfReport<BK, V, TS, B>,
}

pub async fn verify_uniqueness<BK, V, TS, B, C>(
    ctx: C,
    input: Vec<EncryptedOprfReport<BK, V, TS, B>>,
) -> Result<Vec<EncryptedOprfReport<BK, V, TS, B>>, Error>
where
    B: Deref<Target = [u8]>,
    BK: SharedValue,
    V: SharedValue,
    TS: SharedValue,
    C: UpgradableContext + ShardedContext,
{
    let indexed_reports = input
        .iter()
        .enumerate()
        .map(|(index, report)| IndexedEncryptedOprfReport { index, report });

    let resharded = assert_send(reshard(ctx, indexed_reports, |ctx, record_id, _| {
        ctx.pick_shard(record_id)
    }))
    .await?;

    unimplemented!()
}
