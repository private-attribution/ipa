use std::{collections::HashMap, convert::Infallible, sync::Mutex};

use generic_array::GenericArray;
use typenum::{Unsigned, U2, U32, U64};

use crate::{
    ff::Serializable,
    protocol::prss::{
        Endpoint, EndpointInner, FromPrss, FromRandom, GeneratorFactory, PrssIndex,
        SharedRandomness,
    },
};

/// Constructing a seed is only allowed through PRSS.
/// Serialization/Deserialization mechanisms are provided
/// to allow for setup of cross-shard PRSS.
/// This type must never be sent across helper boundaries.
#[derive(Clone, Debug)]
pub struct Seed {
    entropy: [u8; 32],
}

impl Serializable for Seed {
    type Size = U32;
    type DeserializationError = Infallible;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(&self.entropy);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        Ok(Self {
            entropy: (*buf).into(),
        })
    }
}

impl Serializable for (Seed, Seed) {
    type Size = U64;
    type DeserializationError = Infallible;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let (left, right) = buf.split_at_mut(<Seed as Serializable>::Size::USIZE);
        self.0.serialize(GenericArray::from_mut_slice(left));
        self.1.serialize(GenericArray::from_mut_slice(right));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let left = Seed::deserialize(GenericArray::from_slice(
            &buf[..<Seed as Serializable>::Size::USIZE],
        ))?;
        let right = Seed::deserialize(GenericArray::from_slice(
            &buf[<Seed as Serializable>::Size::USIZE..],
        ))?;

        Ok((left, right))
    }
}

impl FromRandom for Seed {
    type SourceLength = U2;

    fn from_random(src: GenericArray<u128, Self::SourceLength>) -> Self {
        let low = src[0];
        let high = src[1];
        let mut entropy = [0u8; 32];
        entropy[..16].copy_from_slice(&low.to_le_bytes());
        entropy[16..].copy_from_slice(&high.to_le_bytes());

        Seed { entropy }
    }
}

impl From<Seed> for GeneratorFactory {
    fn from(value: Seed) -> Self {
        Self::from_secret(&value.entropy)
    }
}

/// This allows setting up cross-shard coordinated randomness, by sampling
/// a shared seed from PRSS and later distributing it across all shards.
pub struct SeededEndpointSetup {
    left: Seed,
    right: Seed,
}

impl FromPrss for SeededEndpointSetup {
    fn from_prss_with<P: SharedRandomness + ?Sized, I: Into<PrssIndex>>(
        prss: &P,
        index: I,
        _params: (),
    ) -> Self {
        let (l, r): (Seed, _) = prss.generate(index.into());

        Self { left: l, right: r }
    }
}

impl SeededEndpointSetup {
    /// Prepare this setup from pregenerated seeds.
    #[must_use]
    pub fn from_seeds(left: Seed, right: Seed) -> Self {
        Self { left, right }
    }

    #[must_use]
    pub fn left_seed(&self) -> &Seed {
        &self.left
    }

    #[must_use]
    pub fn right_seed(&self) -> &Seed {
        &self.right
    }

    /// Finish the setup and generate a working [`Endpoint`]
    #[must_use]
    pub fn setup(self) -> Endpoint {
        let fl = GeneratorFactory::from(self.left);
        let fr = GeneratorFactory::from(self.right);

        Endpoint {
            inner: Mutex::new(EndpointInner {
                left: fl,
                right: fr,
                items: HashMap::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, thread_rng};
    use rand_core::{CryptoRngCore, SeedableRng};

    use crate::{
        protocol::{
            prss::{Endpoint, SeededEndpointSetup, SharedRandomness},
            Gate, RecordId,
        },
        test_fixture::make_participants,
        utils::array::zip3,
    };

    fn setup_new<R: CryptoRngCore>(mut rng: R) -> [SeededEndpointSetup; 3] {
        let participants = make_participants(&mut rng);

        participants
            .each_ref()
            .map(|p| p.indexed(&Gate::default()).generate(RecordId::FIRST))
    }

    fn random_value(endpoint: &Endpoint) -> (u128, u128) {
        endpoint.indexed(&Gate::default()).generate(RecordId::FIRST)
    }

    #[test]
    fn setup() {
        let r1 = setup_new(&mut thread_rng());

        assert_eq!(r1[0].right.entropy, r1[1].left.entropy);
        assert_eq!(r1[1].right.entropy, r1[2].left.entropy);
        assert_eq!(r1[2].right.entropy, r1[0].left.entropy);

        // also make sure seeds are unique
        let r2 = setup_new(&mut thread_rng());

        zip3(r1, r2).map(|(r1, r2)| {
            assert_ne!(r1.right.entropy, r2.right.entropy);
            assert_ne!(r1.left.entropy, r2.left.entropy);
        });
    }

    #[test]
    fn same_seed_same_randomness() {
        let r1 = setup_new(&mut StdRng::seed_from_u64(42)).map(SeededEndpointSetup::setup);
        let r2 = setup_new(&mut StdRng::seed_from_u64(42)).map(SeededEndpointSetup::setup);

        assert_eq!(random_value(&r1[0]), random_value(&r2[0]));
        assert_eq!(random_value(&r1[1]), random_value(&r2[1]));
        assert_eq!(random_value(&r1[2]), random_value(&r2[2]));
    }
}
