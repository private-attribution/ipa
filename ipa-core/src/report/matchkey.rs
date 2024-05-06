#[cfg(all(test, unit_test))]
mod test {
    /* This file contains tests to validate match keys are correctly encrypted across
    client and server code. Each time code is added to client side on FB side to generate
    encrypted match keys, please ensure you add the blob in test_data/fbinfra_integration folder and add a test case to validate it */
    use std::{fs::File, io::Read, ops::Deref};

    use bytes::{BufMut, Bytes};
    use generic_array::GenericArray;
    use hpke::Serializable as _;
    use rand::thread_rng;
    use rand_core::{CryptoRng, RngCore};
    use typenum::{Sum, Unsigned};

    use crate::{
        ff::{boolean_array::BA64, Serializable},
        hpke::{
            open_in_place, seal_in_place, Deserializable, EncapsulationSize, Info, IpaPrivateKey,
            IpaPublicKey, KeyPair, KeyRegistry, PublicKeyRegistry, TagSize,
        },
        report::{
            Epoch, EventType, InvalidReportError, KeyIdentifier, NonAsciiStringError, HELPER_ORIGIN,
        },
        secret_sharing::replicated::{
            semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
        },
    };

    // For test purposes only
    /// A binary report as submitted by a report collector, containing encrypted `MatchKeyReport`
    /// An `EncryptedOprfReport` consists of:
    ///     `ct_mk`: Enc(`match_key`)
    ///     associated data of `ct_mk`: `key_id`, `epoch`, `event_type`, `site_domain`,
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct EncryptedMatchKeyReport<B>
    where
        B: Deref<Target = [u8]>,
    {
        data: B,
    }

    // follows the outline of the implementation of `EncryptedReport`
    // Report structure:
    //  * 0..a: `encap_key_1`
    //  * a..b: `mk_ciphertext`
    //  * d: `event_type`
    //  * d+1: `key_id`
    //  * d+2..d+4: `epoch`
    //  * d+4..: `site_domain`
    impl<B> EncryptedMatchKeyReport<B>
    where
        B: Deref<Target = [u8]>,
    {
        const ENCAP_KEY_MK_OFFSET: usize = 0;
        const CIPHERTEXT_MK_OFFSET: usize = Self::ENCAP_KEY_MK_OFFSET + EncapsulationSize::USIZE;

        const EVENT_TYPE_OFFSET: usize = Self::CIPHERTEXT_MK_OFFSET
            + TagSize::USIZE
            + <Replicated<BA64> as Serializable>::Size::USIZE;

        const KEY_IDENTIFIER_OFFSET: usize = Self::EVENT_TYPE_OFFSET + 1;
        const EPOCH_OFFSET: usize = Self::KEY_IDENTIFIER_OFFSET + 1;
        const SITE_DOMAIN_OFFSET: usize = Self::EPOCH_OFFSET + 2;

        pub fn encap_key_mk(&self) -> &[u8] {
            &self.data[Self::ENCAP_KEY_MK_OFFSET..Self::CIPHERTEXT_MK_OFFSET]
        }

        pub fn mk_ciphertext(&self) -> &[u8] {
            &self.data[Self::CIPHERTEXT_MK_OFFSET..Self::EVENT_TYPE_OFFSET]
        }

        /// ## Panics
        /// Only if a `Report` constructor failed to validate the contents properly, which would be a bug.
        pub fn event_type(&self) -> EventType {
            EventType::try_from(self.data[Self::EVENT_TYPE_OFFSET]).unwrap() // validated on construction
        }

        pub fn key_id(&self) -> KeyIdentifier {
            self.data[Self::KEY_IDENTIFIER_OFFSET]
        }

        /// ## Panics
        /// Never.
        pub fn epoch(&self) -> Epoch {
            u16::from_le_bytes(
                self.data[Self::EPOCH_OFFSET..Self::SITE_DOMAIN_OFFSET]
                    .try_into()
                    .unwrap(),
            )
        }
        /// ## Panics
        /// Only if a `Report` constructor failed to validate the contents properly, which would be a bug.
        pub fn site_domain(&self) -> &str {
            std::str::from_utf8(&self.data[Self::SITE_DOMAIN_OFFSET..]).unwrap()
            // validated on construction
        }

        /// ## Errors
        /// If the report contents are invalid.
        pub fn from_bytes(bytes: B) -> Result<Self, InvalidReportError> {
            if bytes.len() <= Self::SITE_DOMAIN_OFFSET {
                return Err(InvalidReportError::Length(
                    bytes.len(),
                    Self::SITE_DOMAIN_OFFSET,
                ));
            }
            let site_domain = &bytes[Self::SITE_DOMAIN_OFFSET..];

            if !site_domain.is_ascii() {
                return Err(NonAsciiStringError::from(site_domain).into());
            }
            Ok(Self { data: bytes })
        }
        /// ## Errors
        /// If the match key shares in the report cannot be decrypted (e.g. due to a
        /// failure of the authenticated encryption).
        /// ## Panics
        /// Should not panic. Only panics if a `Report` constructor failed to validate the
        /// contents properly, which would be a bug.
        pub fn decrypt(
            &self,
            key_registry: &KeyRegistry<KeyPair>,
        ) -> Result<MatchKeyReport, InvalidReportError> {
            type CTMKLength = Sum<<Replicated<BA64> as Serializable>::Size, TagSize>;

            let info = Info::new(
                self.key_id(),
                self.epoch(),
                self.event_type(),
                HELPER_ORIGIN,
                self.site_domain(),
            )
            .unwrap(); // validated on construction

            let mut ct_mk: GenericArray<u8, CTMKLength> =
                *GenericArray::from_slice(self.mk_ciphertext());

            let plaintext_mk = open_in_place(key_registry, self.encap_key_mk(), &mut ct_mk, &info)?;

            Ok(MatchKeyReport {
                match_key: Replicated::<BA64>::deserialize(GenericArray::from_slice(plaintext_mk))
                    .map_err(|e| InvalidReportError::DeserializationError("matchkey", e.into()))?,
                event_type: self.event_type(),
                epoch: self.epoch(),
                site_domain: self.site_domain().to_owned(),
            })
        }
    }

    impl TryFrom<Bytes> for EncryptedMatchKeyReport<Bytes> {
        type Error = InvalidReportError;

        fn try_from(bytes: Bytes) -> Result<Self, InvalidReportError> {
            EncryptedMatchKeyReport::from_bytes(bytes)
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct MatchKeyReport {
        pub match_key: Replicated<BA64>,
        pub event_type: EventType,
        pub epoch: Epoch,
        pub site_domain: String,
    }

    impl MatchKeyReport {
        /// # Panics
        /// If report length does not fit in `u16`.
        pub fn encrypted_len(&self) -> u16 {
            let len = EncryptedMatchKeyReport::<&[u8]>::SITE_DOMAIN_OFFSET
                + self.site_domain.as_bytes().len();
            len.try_into().unwrap()
        }

        /// # Errors
        /// If there is a problem encrypting the report.
        pub fn encrypt<R: CryptoRng + RngCore>(
            &self,
            key_id: KeyIdentifier,
            key_registry: &impl PublicKeyRegistry,
            rng: &mut R,
        ) -> Result<Vec<u8>, InvalidReportError> {
            let mut out = Vec::with_capacity(usize::from(self.encrypted_len()));
            self.encrypt_to(key_id, key_registry, rng, &mut out)?;
            debug_assert_eq!(out.len(), usize::from(self.encrypted_len()));
            Ok(out)
        }

        /// # Errors
        /// If there is a problem encrypting the report.
        pub fn encrypt_to<R: CryptoRng + RngCore, B: BufMut>(
            &self,
            key_id: KeyIdentifier,
            key_registry: &impl PublicKeyRegistry,
            rng: &mut R,
            out: &mut B,
        ) -> Result<(), InvalidReportError> {
            let info = Info::new(
                key_id,
                self.epoch,
                self.event_type,
                HELPER_ORIGIN,
                self.site_domain.as_ref(),
            )?;

            let mut plaintext_mk = GenericArray::default();
            self.match_key.serialize(&mut plaintext_mk);

            let (encap_key_mk, ciphertext_mk, tag_mk) =
                seal_in_place(key_registry, plaintext_mk.as_mut(), &info, rng)?;

            out.put_slice(&encap_key_mk.to_bytes());
            out.put_slice(ciphertext_mk);
            out.put_slice(&tag_mk.to_bytes());
            out.put_slice(&[u8::from(&self.event_type)]);
            out.put_slice(&[key_id]);
            out.put_slice(&self.epoch.to_le_bytes());
            out.put_slice(self.site_domain.as_bytes());

            Ok(())
        }
    }
    #[test]
    fn test_swift_encryption() {
        let pk = hex::decode("92a6fb666c37c008defd74abf3204ebea685742eab8347b08e2f7c759893947a")
            .unwrap();
        let sk = hex::decode("53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff")
            .unwrap();
        let key_registry = KeyRegistry::from_keys([KeyPair::from((
            IpaPrivateKey::from_bytes(&sk).unwrap(),
            IpaPublicKey::from_bytes(&pk).unwrap(),
        ))]);
        let relative_path = "../test_data/fbinfra_integration/ios_encrypted_matchkey.txt"; // replace with your relative path
                                                                                           // let absolute_path = join(relative_path);
        let mut file = File::open(relative_path).expect("File not found");
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("Error reading file");
        let report = EncryptedMatchKeyReport::<_>::from_bytes(bytes.as_slice()).unwrap();

        let expected = MatchKeyReport {
            match_key: Replicated::new(
                BA64::try_from(1_u128).unwrap(),
                BA64::try_from(2_u128).unwrap(),
            ),
            event_type: EventType::Source,
            epoch: 0,
            site_domain: String::from("www.meta.com"),
        };
        let result = report.decrypt(&key_registry).unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn test_matchkey_decrypt_encrypt() {
        let mut rng = thread_rng();
        let pk = hex::decode("92a6fb666c37c008defd74abf3204ebea685742eab8347b08e2f7c759893947a")
            .unwrap();
        let sk = hex::decode("53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff")
            .unwrap();
        let key_registry = KeyRegistry::from_keys([KeyPair::from((
            IpaPrivateKey::from_bytes(&sk).unwrap(),
            IpaPublicKey::from_bytes(&pk).unwrap(),
        ))]);

        let report = MatchKeyReport {
            match_key: Replicated::new(
                BA64::try_from(1_u128).unwrap(),
                BA64::try_from(2_u128).unwrap(),
            ),
            event_type: EventType::Source,
            epoch: 0,
            site_domain: String::from("www.meta.com"),
        };

        let enc_report_bytes = report.encrypt(0, &key_registry, &mut rng).unwrap();
        let enc_report =
            EncryptedMatchKeyReport::<_>::from_bytes(enc_report_bytes.as_slice()).unwrap();

        let result = enc_report.decrypt(&key_registry).unwrap();
        assert_eq!(report, result);
    }
}
