use std::ops::{Add, Deref};

use generic_array::ArrayLength;
use typenum::{Sum, U16};

use crate::{
    ff::{boolean_array::BA64, Serializable},
    hpke::PrivateKeyRegistry,
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
    /// ## Errors
    /// If the report contents are invalid.
    pub fn from_bytes<P, B, TS>(data: B, key_registry: &P) -> Result<Self, InvalidReportError>
    where
        P: PrivateKeyRegistry,
        B: Deref<Target = [u8]>,
        TS: SharedValue, // this is only needed for the backport from EncryptedOprfReport
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
        let encrypted_oprf_report = EncryptedOprfReport::<BK, V, TS, B>::from_bytes(data)?;
        let oprf_report = encrypted_oprf_report.decrypt(key_registry)?;
        match oprf_report.event_type {
            EventType::Source => Ok(Self::Impression(HybridImpressionReport {
                match_key: oprf_report.match_key,
                breakdown_key: oprf_report.breakdown_key,
            })),
            EventType::Trigger => Ok(Self::Conversion(HybridConversionReport {
                match_key: oprf_report.match_key,
                value: oprf_report.trigger_value,
            })),
        }
    }
}

#[cfg(test)]
mod test {

    use rand::{distributions::Alphanumeric, rngs::ThreadRng, thread_rng, Rng};

    use super::{HybridConversionReport, HybridImpressionReport, HybridReport};
    use crate::{
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
        let hybrid_report2 = HybridReport::<BA8, BA3>::from_bytes::<_, _, BA20>(
            enc_report_bytes.as_slice(),
            &key_registry,
        )
        .unwrap();

        assert_eq!(hybrid_report, hybrid_report2);
    }

    #[test]
    fn convert_to_hybrid_report() {
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
        let hybrid_report2 = HybridReport::<BA8, BA3>::from_bytes::<_, _, BA20>(
            enc_report_bytes.as_slice(),
            &key_registry,
        )
        .unwrap();

        assert_eq!(hybrid_report, hybrid_report2);
    }
}
