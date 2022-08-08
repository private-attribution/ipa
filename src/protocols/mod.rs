/// unique protocol identifier, used to disambiguate messages of the same type sent towards
/// the same set of helpers that perform multiple concurrent computations
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct ProtocolId(u32);

impl From<u32> for ProtocolId {
    fn from(v: u32) -> Self {
        ProtocolId(v)
    }
}
