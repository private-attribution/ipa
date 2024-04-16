use crate::{ff::Field, protocol::context::dzkp_validator::SegmentEntry};

/// Trait for fields compatible with DZKPs
/// Field needs to support conversion to `SegmentEntry`, i.e. `to_segment_entry` which is required by DZKPs
#[allow(dead_code)]
pub trait DZKPCompatibleField: Field {
    fn as_segment_entry(&self) -> SegmentEntry<'_>;
}
