/// unique protocol identifier, used to disambiguate messages of the same type sent towards
/// the same set of helpers that perform multiple concurrent computations
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct ProtocolId(u128);

impl From<u128> for ProtocolId {
    fn from(v: u128) -> Self {
        ProtocolId(v)
    }
}
