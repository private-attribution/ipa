use std::{collections::HashSet, ops::Add};

use bytes::Bytes;
use generic_array::ArrayLength;
use rand_core::{CryptoRng, RngCore};
use typenum::{Sum, Unsigned, U16};

use crate::{
    error::Error,
    ff::{boolean_array::BA64, Serializable},
    hpke::{EncapsulationSize, PrivateKeyRegistry, PublicKeyRegistry, TagSize},
    report::{EncryptedOprfReport, EventType, InvalidReportError, KeyIdentifier},
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridImpressionReport<BK>
where
    BK: SharedValue,
{
    match_key: Replicated<BA64>,
    breakdown_key: Replicated<BK>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridConversionReport<V>
where
    V: SharedValue,
{
    match_key: Replicated<BA64>,
    value: Replicated<V>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HybridReport<BK, V>
where
    BK: SharedValue,
    V: SharedValue,
{
    Impression(HybridImpressionReport<BK>),
    Conversion(HybridConversionReport<V>),
}

#[allow(dead_code)]
pub struct HybridImpressionInfo<'a> {
    pub key_id: KeyIdentifier,
    pub helper_origin: &'a str,
}

#[allow(dead_code)]
pub struct HybridConversionInfo<'a> {
    pub key_id: KeyIdentifier,
    pub helper_origin: &'a str,
    pub converion_site_domain: &'a str,
    pub timestamp: u64,
    pub epsilon: f64,
    pub sensitivity: f64,
}

#[allow(dead_code)]
pub enum HybridInfo<'a> {
    Impression(HybridImpressionInfo<'a>),
    Conversion(HybridConversionInfo<'a>),
}

impl<BK, V> HybridReport<BK, V>
where
    BK: SharedValue,
    V: SharedValue,
{
    /// # Errors
    /// If there is a problem encrypting the report.
    pub fn encrypt<R: CryptoRng + RngCore>(
        &self,
        _key_id: KeyIdentifier,
        _key_registry: &impl PublicKeyRegistry,
        _rng: &mut R,
    ) -> Result<Vec<u8>, InvalidReportError> {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct EncryptedHybridReport {
    bytes: Bytes,
}

impl EncryptedHybridReport {
    /// ## Errors
    /// If the report fails to decrypt
    pub fn decrypt<P, BK, V, TS>(
        &self,
        key_registry: &P,
    ) -> Result<HybridReport<BK, V>, InvalidReportError>
    where
        P: PrivateKeyRegistry,
        BK: SharedValue,
        V: SharedValue,
        TS: SharedValue,
        Replicated<BK>: Serializable,
        Replicated<V>: Serializable,
        Replicated<TS>: Serializable,
        <Replicated<BK> as Serializable>::Size: Add<<Replicated<V> as Serializable>::Size>,
        Sum<<Replicated<BK> as Serializable>::Size, <Replicated<V> as Serializable>::Size>:
            Add<<Replicated<TS> as Serializable>::Size>,
        Sum<
            Sum<<Replicated<BK> as Serializable>::Size, <Replicated<V> as Serializable>::Size>,
            <Replicated<TS> as Serializable>::Size,
        >: Add<U16>,
        Sum<
            Sum<
                Sum<<Replicated<BK> as Serializable>::Size, <Replicated<V> as Serializable>::Size>,
                <Replicated<TS> as Serializable>::Size,
            >,
            U16,
        >: ArrayLength,
    {
        let encrypted_oprf_report =
            EncryptedOprfReport::<BK, V, TS, Bytes>::try_from(self.bytes.clone())?;
        let oprf_report = encrypted_oprf_report.decrypt(key_registry)?;
        match oprf_report.event_type {
            EventType::Source => Ok(HybridReport::Impression(HybridImpressionReport {
                match_key: oprf_report.match_key,
                breakdown_key: oprf_report.breakdown_key,
            })),
            EventType::Trigger => Ok(HybridReport::Conversion(HybridConversionReport {
                match_key: oprf_report.match_key,
                value: oprf_report.trigger_value,
            })),
        }
    }

    /// TODO: update these when we produce a proper encapsulation of
    /// `EncryptedHybridReport`, rather than pigggybacking on `EncryptedOprfReport`
    pub fn mk_ciphertext(&self) -> &[u8] {
        let encap_key_mk_offset: usize = 0;
        let ciphertext_mk_offset: usize = encap_key_mk_offset + EncapsulationSize::USIZE;
        let encap_key_btt_offset: usize =
            ciphertext_mk_offset + TagSize::USIZE + <Replicated<BA64> as Serializable>::Size::USIZE;

        &self.bytes[ciphertext_mk_offset..encap_key_btt_offset]
    }
}

impl TryFrom<Bytes> for EncryptedHybridReport {
    type Error = InvalidReportError;

    fn try_from(bytes: Bytes) -> Result<Self, InvalidReportError> {
        Ok(EncryptedHybridReport { bytes })
    }
}

const TAG_SIZE: usize = TagSize::USIZE;

#[derive(Clone)]
pub struct UniqueTag {
    bytes: [u8; TAG_SIZE],
}

pub trait UniqueBytes {
    fn unique_bytes(&self) -> [u8; TAG_SIZE];
}

impl UniqueBytes for UniqueTag {
    fn unique_bytes(&self) -> [u8; TAG_SIZE] {
        self.bytes
    }
}

impl UniqueBytes for EncryptedHybridReport {
    /// We use the `TagSize` (the first 16 bytes of the ciphertext) for collision-detection
    /// See [analysis here for uniqueness](https://eprint.iacr.org/2019/624)
    fn unique_bytes(&self) -> [u8; TAG_SIZE] {
        let slice = &self.mk_ciphertext()[0..TAG_SIZE];
        let mut array = [0u8; TAG_SIZE];
        array.copy_from_slice(slice);
        array
    }
}

impl UniqueTag {
    // Function to attempt to create a UniqueTag from a UniqueBytes implementor
    pub fn from_unique_bytes<T: UniqueBytes>(item: &T) -> Self {
        UniqueTag {
            bytes: item.unique_bytes(),
        }
    }
}

#[derive(Debug)]
pub struct UniqueTagValidator {
    hash_set: HashSet<[u8; TAG_SIZE]>,
    check_counter: usize,
}

impl UniqueTagValidator {
    #[must_use]
    pub fn new(size: usize) -> Self {
        UniqueTagValidator {
            hash_set: HashSet::with_capacity(size),
            check_counter: 0,
        }
    }
    fn insert(&mut self, value: [u8; TAG_SIZE]) -> bool {
        self.hash_set.insert(value)
    }
    /// Checks that item is unique among all checked thus far
    ///
    /// ## Errors
    /// if the item inserted is not unique among all checked thus far
    pub fn check_duplicate<U: UniqueBytes>(&mut self, item: &U) -> Result<(), Error> {
        self.check_counter += 1;
        if self.insert(item.unique_bytes()) {
            Ok(())
        } else {
            Err(Error::DuplicateBytes(self.check_counter))
        }
    }
    /// Checks that an iter of items is unique among the iter and any other items checked thus far
    ///
    /// ## Errors
    /// if the and item inserted is not unique among all in this batch and checked previously
    pub fn check_duplicates<U: UniqueBytes>(&mut self, items: &[U]) -> Result<(), Error> {
        items
            .iter()
            .try_for_each(|item| self.check_duplicate(item))?;
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use rand::{distributions::Alphanumeric, rngs::ThreadRng, thread_rng, Rng};

    use super::{
        EncryptedHybridReport, HybridConversionReport, HybridImpressionReport, HybridReport,
        UniqueTag, UniqueTagValidator,
    };
    use crate::{
        error::Error,
        ff::boolean_array::{BA20, BA3, BA8},
        hpke::{KeyPair, KeyRegistry},
        report::{EventType, OprfReport},
        secret_sharing::replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
    };

    fn build_oprf_report(event_type: EventType, rng: &mut ThreadRng) -> OprfReport<BA8, BA3, BA20> {
        OprfReport::<BA8, BA3, BA20> {
            match_key: AdditiveShare::new(rng.gen(), rng.gen()),
            timestamp: AdditiveShare::new(rng.gen(), rng.gen()),
            breakdown_key: AdditiveShare::new(rng.gen(), rng.gen()),
            trigger_value: AdditiveShare::new(rng.gen(), rng.gen()),
            event_type,
            epoch: rng.gen(),
            site_domain: (rng)
                .sample_iter(Alphanumeric)
                .map(char::from)
                .take(10)
                .collect(),
        }
    }

    fn generate_random_bytes() -> [u8; 16] {
        let mut rng = thread_rng();
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes[..]);
        bytes
    }

    #[test]
    fn convert_to_hybrid_impression_report() {
        let mut rng = thread_rng();

        let b = EventType::Source;

        let oprf_report = build_oprf_report(b, &mut rng);
        let hybrid_report = HybridReport::Impression::<BA8, BA3>(HybridImpressionReport::<BA8> {
            match_key: oprf_report.match_key.clone(),
            breakdown_key: oprf_report.breakdown_key.clone(),
        });

        let key_registry = KeyRegistry::<KeyPair>::random(1, &mut rng);
        let key_id = 0;

        let enc_report_bytes = oprf_report
            .encrypt(key_id, &key_registry, &mut rng)
            .unwrap();
        let enc_report = EncryptedHybridReport {
            bytes: enc_report_bytes.into(),
        };

        let hybrid_report2 = enc_report
            .decrypt::<_, BA8, BA3, BA20>(&key_registry)
            .unwrap();

        assert_eq!(hybrid_report, hybrid_report2);
    }

    #[test]
    fn convert_to_hybrid_conversion_report() {
        let mut rng = thread_rng();

        let b = EventType::Trigger;

        let oprf_report = build_oprf_report(b, &mut rng);
        let hybrid_report = HybridReport::Conversion::<BA8, BA3>(HybridConversionReport::<BA3> {
            match_key: oprf_report.match_key.clone(),
            value: oprf_report.trigger_value.clone(),
        });

        let key_registry = KeyRegistry::<KeyPair>::random(1, &mut rng);
        let key_id = 0;

        let enc_report_bytes = oprf_report
            .encrypt(key_id, &key_registry, &mut rng)
            .unwrap();
        let enc_report = EncryptedHybridReport {
            bytes: enc_report_bytes.into(),
        };
        let hybrid_report2 = enc_report
            .decrypt::<_, BA8, BA3, BA20>(&key_registry)
            .unwrap();

        assert_eq!(hybrid_report, hybrid_report2);
    }

    #[test]
    fn unique_encrypted_hybrid_reports() {
        let tag1 = UniqueTag {
            bytes: generate_random_bytes(),
        };
        let tag2 = UniqueTag {
            bytes: generate_random_bytes(),
        };
        let tag3 = UniqueTag {
            bytes: generate_random_bytes(),
        };
        let tag4 = UniqueTag {
            bytes: generate_random_bytes(),
        };

        let mut unique_bytes = UniqueTagValidator::new(4);

        unique_bytes.check_duplicate(&tag1).unwrap();

        unique_bytes
            .check_duplicates(&[tag2.clone(), tag3.clone()])
            .unwrap();
        let expected_err = unique_bytes.check_duplicate(&tag2);
        assert!(matches!(expected_err, Err(Error::DuplicateBytes(4))));

        let expected_err = unique_bytes.check_duplicates(&[tag4, tag3]);
        assert!(matches!(expected_err, Err(Error::DuplicateBytes(6))));
    }
}
