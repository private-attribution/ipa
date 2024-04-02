use std::convert::Infallible;

use generic_array::GenericArray;
use sha2::{
    digest::{Output, OutputSizeUser},
    Digest, Sha256,
};

use crate::{
    ff::{Field, Serializable},
    protocol::prss::FromRandomU128,
};

#[derive(Debug, PartialEq)]
pub struct Hash(Output<Sha256>);

impl Serializable for Hash {
    type Size = <Sha256 as OutputSizeUser>::OutputSize;

    type DeserializationError = Infallible;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(&self.0);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        Ok(Hash(*Output::<Sha256>::from_slice(buf)))
    }
}

pub fn compute_hash<'a, I, S>(input: I) -> Hash
where
    I: IntoIterator<Item = &'a S>,
    S: Serializable + 'a,
{
    // set up hash
    let mut sha = Sha256::new();
    let mut buf = GenericArray::default();
    let mut is_empty = true;

    // set state
    for x in input {
        is_empty = false;
        x.serialize(&mut buf);
        sha.update(&buf);
    }

    assert!(!is_empty, "must not provide an empty iterator");
    // compute hash
    Hash(sha.finalize())
}

/// This function takes two hash a vector of field elements into a single field element
/// # Panics
/// does not panic
pub fn hash_to_field<F>(left: &Hash, right: &Hash) -> F
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
    use generic_array::{sequence::GenericSequence, GenericArray};
    use rand::{thread_rng, Rng};
    use typenum::U8;

    use super::{compute_hash, Hash};
    use crate::{
        ff::{Fp31, Fp32BitPrime, Serializable},
        protocol::ipa_prf::malicious_security::hashing::hash_to_field,
    };

    #[test]
    fn can_serialize_and_deserialize() {
        let mut rng = thread_rng();
        let list: GenericArray<Fp32BitPrime, U8> =
            GenericArray::generate(|_| rng.gen::<Fp32BitPrime>());
        let hash: Hash = compute_hash(&list);
        let mut buf: GenericArray<u8, _> = GenericArray::default();
        hash.serialize(&mut buf);
        let deserialized_hash = Hash::deserialize(&buf);
        assert_eq!(hash, deserialized_hash.unwrap());
    }

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

        // swapping two elements should change the hash
        let mut index_1 = 0;
        let mut index_2 = 0;
        // There is a 1 in 31 chance that these two elements are the exact same value.
        // To make sure this doesn't become a flaky test, let's just pick two different
        // elements to swap when that happens.
        // This will be an infinite loop if all elements are the same. The chances of that
        // are (1 / 31) ^ (LIST_LENGTH - 1)
        // which is 1 in 923,521 when LIST_LENGTH is 5. I'm OK with that.
        while list[index_1] == list[index_2] {
            index_1 = rng.gen_range(0..LIST_LENGTH);
            index_2 = (index_1 + rng.gen_range(1..LIST_LENGTH)) % LIST_LENGTH;
        }
        list.swap(index_1, index_2);

        let hash_3 = compute_hash(&list);

        assert_ne!(
            hash_2, hash_3,
            "The hash should change if two elements are swapped"
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
        let r1: Fp32BitPrime = hash_to_field(&compute_hash(&left), &compute_hash(&right));

        // modify one, randomly selected element in the list
        let random_index = rng.gen::<usize>() % LIST_LENGTH;
        // There is a 1 in 2^32 chance that we generate exactly the same value and the test fails.
        let modified_value = rng.gen::<Fp32BitPrime>();
        if rng.gen::<bool>() {
            left[random_index] = modified_value;
        } else {
            right[random_index] = modified_value;
        }

        let r2: Fp32BitPrime = hash_to_field(&compute_hash(&left), &compute_hash(&right));

        assert_ne!(
            r1, r2,
            "any modification to either list should change the hashed field element"
        );
    }
}
