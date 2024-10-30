use std::convert::Infallible;

use generic_array::GenericArray;
use sha2::{
    digest::{Output, OutputSizeUser},
    Digest, Sha256,
};

use crate::{
    ff::{PrimeField, Serializable},
    helpers::MpcMessage,
    protocol::prss::FromRandomU128,
};

#[derive(Clone, Debug, Default, PartialEq)]
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

/// This trait works similar to `Borrow` in the sense
/// that it is implemented for owned values and references.
///
/// The advantage over `Borrow` is that types can be
/// inferred by the compiler when using references.
pub trait SerializeAs<T: Serializable> {
    fn serialize(self, buf: &mut GenericArray<u8, T::Size>);
}

impl<T: Serializable> SerializeAs<T> for T {
    fn serialize(self, buf: &mut GenericArray<u8, <T as Serializable>::Size>) {
        <T as Serializable>::serialize(&self, buf);
    }
}

impl<'a, T: Serializable> SerializeAs<T> for &'a T {
    fn serialize(self, buf: &mut GenericArray<u8, <T as Serializable>::Size>) {
        <T as Serializable>::serialize(self, buf);
    }
}

impl MpcMessage for Hash {}

fn compute_hash_internal<I, T, S>(input: I) -> (Hash, bool)
where
    I: IntoIterator<Item = T>,
    T: SerializeAs<S>,
    S: Serializable,
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

    // compute hash
    (Hash(sha.finalize()), is_empty)
}

/// Computes Hash of serializable values from an iterator
///
/// ## Panics
/// Panics if an empty input is provided. This can offer defense-in-depth by helping to
/// prevent fail-open bugs when the input should never be empty.
pub fn compute_hash<I, T, S>(input: I) -> Hash
where
    I: IntoIterator<Item = T>,
    T: SerializeAs<S>,
    S: Serializable,
{
    let (hash, empty) = compute_hash_internal(input);
    assert!(!empty, "must not provide an empty iterator");
    hash
}

/// Computes Hash of serializable values from an iterator
///
/// Unlike `compute_hash`, this version accepts empty inputs.
pub fn compute_possibly_empty_hash<I, T, S>(iter: I) -> Hash
where
    I: IntoIterator<Item = T>,
    T: SerializeAs<S>,
    S: Serializable,
{
    let (hash, _) = compute_hash_internal(iter);
    hash
}

/// This function takes two hashes, combines them together and returns a single field element.
///
/// Its use is tailored to malicious security requirements where the random challenge point `r`
/// must be uniformly drawn from the field `F`, with the constraint that it does NOT appear
/// in the set {0, 1, ..., L-1}.
/// In the paper [`ZKP_PROOF`] this is shown on step (2.f) of protocol C.2.1
/// on page 21 where it says: "The parties call `F_{coin}` to receive a random `r ∈ F_{p} \ [L]`"
/// When using Fiat-Shamir to generate the random challenge point, we simply constrain
/// the conversion from SHA-derived-entropy to field element to only generate valid values,
/// rather than use rejection sampling. The range [0, L) is provided through `exclude_to` parameter.
///
/// [`ZKP_PROOF`]: https://eprint.iacr.org/2023/909.pdf
/// # Panics
/// If field size is too large compared to 128 bits of entropy required to generate `r` or
/// if exclude range is greater than half size of the field `F`.
pub fn hash_to_field<F>(left: &Hash, right: &Hash, exclude_to: u128) -> F
where
    F: PrimeField + FromRandomU128,
{
    let prime = F::PRIME.into();
    assert!(
        F::BITS <= 64,
        "Field size {f_sz} is too large, compared to the 128 bits of entropy, \
        which will result in excessive bias when converting to a field element",
        f_sz = F::BITS
    );
    assert!(
        2 * exclude_to < prime,
        "Exclude range {exclude_range:?} is too large relative to the size of the field {prime:?}",
        exclude_range = 0..exclude_to,
    );

    // set state
    let combine = compute_hash([left, right]);
    let mut buf = GenericArray::default();
    combine.serialize(&mut buf);

    // compute hash as a field element
    // ideally we would generate `hash` as a `[u8;F::Size]` and `deserialize` it to generate `r`
    // however, deserialize might fail for some fields so we use `truncate_from` instead
    // this results in at most 128 bits of security/collision probability rather than 256 bits as offered by `Sha256`
    // for field elements of size less than 129 bits, this does not make a difference
    let val = u128::from_le_bytes(buf[..16].try_into().unwrap());

    F::truncate_from(val % (prime - exclude_to) + exclude_to)
}

#[cfg(all(test, unit_test))]
mod test {
    use std::iter;

    use generic_array::{sequence::GenericSequence, GenericArray};
    use rand::{thread_rng, Rng};
    use typenum::U8;

    use super::{compute_hash, compute_possibly_empty_hash, Hash};
    use crate::{
        ff::{Fp31, Fp32BitPrime, Serializable},
        helpers::hashing::hash_to_field,
    };

    #[test]
    fn can_serialize_and_deserialize() {
        let mut rng = thread_rng();
        let list: GenericArray<Fp32BitPrime, U8> =
            GenericArray::generate(|_| rng.gen::<Fp32BitPrime>());
        let hash: Hash = compute_hash(list);
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
        const EXCLUDE: u128 = 7;

        let mut rng = thread_rng();

        let mut left = Vec::with_capacity(LIST_LENGTH);
        let mut right = Vec::with_capacity(LIST_LENGTH);
        for _ in 0..LIST_LENGTH {
            left.push(rng.gen::<Fp32BitPrime>());
            right.push(rng.gen::<Fp32BitPrime>());
        }
        let r1: Fp32BitPrime = hash_to_field(&compute_hash(&left), &compute_hash(&right), EXCLUDE);

        // modify one, randomly selected element in the list
        let random_index = rng.gen::<usize>() % LIST_LENGTH;
        // There is a 1 in 2^32 chance that we generate exactly the same value and the test fails.
        let modified_value = rng.gen::<Fp32BitPrime>();
        if rng.gen::<bool>() {
            left[random_index] = modified_value;
        } else {
            right[random_index] = modified_value;
        }

        let r2: Fp32BitPrime = hash_to_field(&compute_hash(&left), &compute_hash(&right), EXCLUDE);

        assert_ne!(
            r1, r2,
            "any modification to either list should change the hashed field element"
        );
    }

    #[test]
    fn check_hash_from_owned_values() {
        let mut rng = thread_rng();
        let vec = (0..100).map(|_| rng.gen::<Fp31>()).collect::<Vec<_>>();
        assert_eq!(compute_hash(&vec), compute_hash(vec));
    }

    #[test]
    #[should_panic(expected = "must not provide an empty iterator")]
    fn empty_reject() {
        compute_hash(iter::empty::<Fp31>());
    }

    #[test]
    fn empty_accept() {
        // SHA256 hash of zero-length input.
        let empty_hash = Hash::deserialize(GenericArray::from_slice(
            &hex::decode(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap(),
        ))
        .unwrap();
        assert_eq!(
            compute_possibly_empty_hash(iter::empty::<Fp31>()),
            empty_hash
        );
    }
}
