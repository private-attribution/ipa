use std::convert::Infallible;

use generic_array::GenericArray;
use sha2::{Digest, Sha256};
use typenum::U32;

use crate::{
    ff::{Field, Serializable},
    helpers::Message,
    protocol::prss::FromRandomU128,
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
pub fn compute_hash<'a, I, S>(input: I) -> Hash
where
    I: IntoIterator<Item = &'a S>,
    S: Serializable + 'a,
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
pub fn hash_to_field<F>(left: Hash, right: Hash) -> F
where
    F: Field + FromRandomU128,
{
    // set up hash
    let mut sha = Sha256::new();

    // set state
    let mut buf = GenericArray::default();
    left.serialize(&mut buf);
    sha.update(buf);
    right.serialize(&mut buf);
    sha.update(buf);

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
    use rand::{thread_rng, Rng};

    use crate::{
        ff::{Fp31, Fp32BitPrime},
        protocol::ipa_prf::malicious_security::hashing::hash_to_field,
    };

    use super::compute_hash;

    #[test]
    fn hash_changes() {
        const LIST_LENGTH: usize = 5;

        let mut rng = thread_rng();

        let mut list: Vec<Fp31> = Vec::with_capacity(LIST_LENGTH);
        for _ in 0..LIST_LENGTH {
            list.push(rng.gen::<Fp31>());
        }
        let hash_1 = compute_hash(&list);

        // modify one, randomly selected element in the list
        let random_index = rng.gen::<usize>() % LIST_LENGTH;
        let mut different_field_element = list[random_index];
        while different_field_element == list[random_index] {
            different_field_element = rng.gen::<Fp31>();
        }
        list[random_index] = different_field_element;

        let hash_2 = compute_hash(&list);

        assert_ne!(
            hash_1, hash_2,
            "The hash should change if the input is different"
        );
    }

    #[test]
    fn field_element_changes() {
        const LIST_LENGTH: usize = 5;

        let mut rng = thread_rng();

        let mut left = Vec::with_capacity(LIST_LENGTH);
        let mut right = Vec::with_capacity(LIST_LENGTH);
        for _ in 0..LIST_LENGTH {
            left.push(rng.gen::<Fp32BitPrime>());
            right.push(rng.gen::<Fp32BitPrime>());
        }
        let r1: Fp32BitPrime = hash_to_field(compute_hash(&left), compute_hash(&right));

        // modify one, randomly selected element in the list
        let random_index = rng.gen::<usize>() % LIST_LENGTH;
        // There is a 1 in 2^32 chance that we generate exactly the same value and the test fails.
        let modified_value = rng.gen::<Fp32BitPrime>();
        if rng.gen::<bool>() {
            left[random_index] = modified_value;
        } else {
            right[random_index] = modified_value;
        }

        let r2: Fp32BitPrime = hash_to_field(compute_hash(&left), compute_hash(&right));

        assert_ne!(
            r1, r2,
            "any modification to either list should change the hashed field element"
        );
    }
}
