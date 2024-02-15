use async_trait::async_trait;

use crate::{
    protocol::{context::Context, RecordBinding, RecordId},
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
};

#[async_trait]
pub trait PartialReveal<C: Context, B: RecordBinding>: Sized {
    type Output;
}

/// Similar to reveal, however one helper party does not receive the output
/// ![Reveal steps][reveal]
/// Each helper sends their left share to the right helper. The helper then reconstructs their secret by adding the three shares
/// i.e. their own shares and received share.
#[async_trait]
// #[embed_doc_image("reveal", "images/reveal.png")]
impl<C: Context, V: SharedValue> PartialReveal<C, RecordId> for Replicated<V> {
    type Output = V;
}

#[cfg(all(test, unit_test))]
mod tests {
    // No tests :(, see 'protocol/ipa_prf/boolean_ops/share_conversion_aby.rs'
}
