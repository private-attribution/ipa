use ipa_step_derive::CompactStep;

/// Special context that is used when values generated using the standard method are larger
/// than the prime for the field. It is grossly inefficient to use, because communications
/// are unbuffered, but a prime that is close to a power of 2 helps reduce how often we need it.
#[derive(CompactStep)]
pub(crate) struct FallbackStep;
