use std::convert::Infallible;

use generic_array::GenericArray;
use sha2::{Digest, Sha256};
use typenum::{Unsigned, U32};

use crate::{
    ff::{Field, Serializable},
    helpers::Message,
    secret_sharing::SharedValue,
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Hash(pub(crate) GenericArray<u8, U32>);

impl Serializable for Hash {
    type Size = U32;
    type DeserializationError = Infallible;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        *buf = self.0;
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        Ok(Hash(*buf))
    }
}

impl Message for Hash {}

/// This function allows to compute a hash of a slice of shared values.
/// The output is a single `Hash` struct that can be sent over the network channel to other helper parties.
pub fn compute_hash<S>(input: &[S]) -> Hash
where
    S: SharedValue,
{
    // set up hash
    let mut sha = Sha256::new();
    // set state
    for x in input {
        let mut buf = GenericArray::default();
        x.serialize(&mut buf);
        sha.update(buf);
    }
    // compute hash
    Hash(*GenericArray::<u8, U32>::from_slice(&sha.finalize()[0..32]))
}

/// This function allows to hash a vector of field elements into a single field element
/// # Panics
/// does not panic
pub fn hash_to_field<F>(input: &[F]) -> F
where
    F: Field,
{
    // set up hash
    let mut sha = Sha256::new();
    // set state
    for x in input {
        let mut buf = GenericArray::default();
        x.serialize(&mut buf);
        sha.update(buf);
    }
    // compute hash as a field element
    // ideally we would generate `hash` as a `[u8;F::Size]` and `deserialize` it to generate `r`
    // however, deserialize might fail for some fields so we use `from_random_128` instead
    // this results in at most 128 bits of security/collision probability rather than 256 bits as offered by `Sha256`
    // for field elements of size less than 129 bits, this does not make a difference
    F::from_random_u128(u128::from_le_bytes(
        sha.finalize()[0..16].try_into().unwrap(),
    ))
}

#[cfg(all(test, unit_test))]
mod test {
    // correctness of `compute_hash` is tested in `validate_replicated_shares`
    // correctness of `hash_to_field` is tested in `fiat_shamir`
}
