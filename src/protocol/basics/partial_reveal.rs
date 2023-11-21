use async_trait::async_trait;
use futures::future::try_join;

use crate::{
    error::Error,
    helpers::{Direction, Role},
    protocol::{
        context::{Context, UpgradedMaliciousContext},
        RecordBinding, RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
        },
        WeakSharedValue,
    },
};

/// Trait for partial reveal protocol to open a shared secret to all helpers except helper `left_out` inside the MPC ring.
#[async_trait]
pub trait PartialReveal<C: Context, B: RecordBinding>: Sized {
    type Output;
    /// reveal the secret to all helpers in MPC circuit. Note that after method is called,
    /// it must be assumed that the secret value has been revealed to at least one of the helpers.
    /// Even in case when method never terminates, returns an error, etc.
    async fn partial_reveal<'fut>(
        &self,
        ctx: C,
        record_binding: B,
        left_out: Role,
    ) -> Result<Option<Self::Output>, Error>
    where
        C: 'fut;
}

/// Similar to reveal, however one helper party does not receive the output
/// ![Reveal steps][reveal]
/// Each helper sends their left share to the right helper. The helper then reconstructs their secret by adding the three shares
/// i.e. their own shares and received share.
#[async_trait]
// #[embed_doc_image("reveal", "images/reveal.png")]
impl<C: Context, V: WeakSharedValue> PartialReveal<C, RecordId> for Replicated<V> {
    type Output = V;

    async fn partial_reveal<'fut>(
        &self,
        ctx: C,
        record_id: RecordId,
        left_out: Role,
    ) -> Result<Option<V>, Error>
    where
        C: 'fut,
    {
        let (left, right) = self.as_tuple();

        // send except to left_out
        if ctx.role().peer(Direction::Right) != left_out {
            ctx.send_channel(ctx.role().peer(Direction::Right))
                .send(record_id, left)
                .await?;
        }

        if ctx.role() == left_out {
            Ok(None)
        } else {
            let share = ctx
                .recv_channel(ctx.role().peer(Direction::Left))
                .receive(record_id)
                .await?;

            Ok(Some(left + right + share))
        }
    }
}

#[async_trait]
impl<'a, F: ExtendableField> PartialReveal<UpgradedMaliciousContext<'a, F>, RecordId>
    for MaliciousReplicated<F>
{
    type Output = F;

    async fn partial_reveal<'fut>(
        &self,
        ctx: UpgradedMaliciousContext<'a, F>,
        record_id: RecordId,
        left_out: Role,
    ) -> Result<Option<F>, Error>
    where
        UpgradedMaliciousContext<'a, F>: 'fut,
    {
        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let (left, right) = self.x().access_without_downgrade().as_tuple();
        let left_sender = ctx.send_channel(ctx.role().peer(Direction::Left));
        let left_receiver = ctx.recv_channel::<F>(ctx.role().peer(Direction::Left));
        let right_sender = ctx.send_channel(ctx.role().peer(Direction::Right));
        let right_receiver = ctx.recv_channel::<F>(ctx.role().peer(Direction::Right));

        // Send share to helpers to the right and left
        // send except to left_out
        if ctx.role().peer(Direction::Left) != left_out {
            left_sender.send(record_id, right).await?;
        }
        if ctx.role().peer(Direction::Right) != left_out {
            right_sender.send(record_id, left).await?;
        }
        if ctx.role() == left_out {
            Ok(None)
        } else {
            let (share_from_left, share_from_right) = try_join(
                left_receiver.receive(record_id),
                right_receiver.receive(record_id),
            )
            .await?;

            if share_from_left == share_from_right {
                Ok(Some(left + right + share_from_left))
            } else {
                Err(Error::MaliciousRevealFailed)
            }
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    // No tests :(, see 'protocol/ipa_prf/boolean_ops/share_conversion_aby.rs'
}
