//! Supported vectorizations

use crate::{
    ff::{
        boolean::Boolean,
        boolean_array::{BA16, BA20, BA256, BA3, BA32, BA5, BA64, BA8},
        ec_prime_field::Fp25519,
        Fp32BitPrime,
    },
    protocol::{
        context::{dzkp_field::DZKPCompatibleField, dzkp_validator::SegmentEntry},
        ipa_prf::PRF_CHUNK,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, FieldSimd, FieldVectorizable,
        ReplicatedSecretSharing, Vectorizable,
    },
};

impl FieldSimd<32> for Fp32BitPrime {}

impl FieldSimd<PRF_CHUNK> for Fp25519 {}

macro_rules! boolean_vector {
    ($modname:ident, $dim:expr, $vec:ty) => {
        mod $modname {
            use super::*;

            impl Vectorizable<$dim> for Boolean {
                type Array = $vec;
            }

            impl FieldVectorizable<$dim> for Boolean {
                type ArrayAlias = $vec;
            }

            impl FieldSimd<$dim> for Boolean {}

            impl DZKPCompatibleField<$dim> for Boolean {
                fn as_segment_entry(
                    array: &<Self as Vectorizable<$dim>>::Array,
                ) -> SegmentEntry<'_> {
                    SegmentEntry::from_bitslice(array.as_bitslice())
                }
            }

            impl From<AdditiveShare<$vec>> for AdditiveShare<Boolean, $dim> {
                fn from(value: AdditiveShare<$vec>) -> Self {
                    AdditiveShare::new_arr(value.left(), value.right())
                }
            }

            impl From<AdditiveShare<Boolean, $dim>> for AdditiveShare<$vec> {
                fn from(value: AdditiveShare<Boolean, $dim>) -> Self {
                    AdditiveShare::new(*value.left_arr(), *value.right_arr())
                }
            }

            #[cfg(all(test, unit_test))]
            mod tests {
                use std::iter::zip;

                use super::*;
                use crate::{
                    error::Error,
                    protocol::{
                        basics::select,
                        context::{dzkp_validator::DZKPValidator, Context, UpgradableContext},
                        RecordId,
                    },
                    rand::{thread_rng, Rng},
                    secret_sharing::into_shares::IntoShares,
                    test_fixture::{join3v, Reconstruct, TestWorld},
                };

                #[tokio::test]
                async fn simplest_circuit_malicious() {
                    let world = TestWorld::default();
                    let context = world.malicious_contexts();
                    let mut rng = thread_rng();

                    let bit = rng.gen::<Boolean>();
                    let a = rng.gen::<$vec>();
                    let b = rng.gen::<$vec>();

                    let bit_shares = bit.share_with(&mut rng);
                    let a_shares = a.share_with(&mut rng);
                    let b_shares = b.share_with(&mut rng);

                    let futures = zip(context.iter(), zip(bit_shares, zip(a_shares, b_shares)))
                        .map(|(ctx, (bit_share, (a_share, b_share)))| async move {
                            let v = ctx.clone().dzkp_validator(1);
                            let m_ctx = v.context();

                            let result = select(
                                m_ctx.set_total_records(1),
                                RecordId::from(0),
                                &bit_share,
                                &a_share,
                                &b_share,
                            )
                            .await?;

                            v.validate().await?;

                            Ok::<_, Error>(result)
                        });

                    let [ab0, ab1, ab2] = join3v(futures).await;

                    let ab = [ab0, ab1, ab2].reconstruct();

                    assert_eq!(ab, if bit.into() { a } else { b });
                }

                #[tokio::test]
                async fn simplest_circuit_semi_honest() {
                    let world = TestWorld::default();
                    let context = world.contexts();
                    let mut rng = thread_rng();

                    let bit = rng.gen::<Boolean>();
                    let a = rng.gen::<$vec>();
                    let b = rng.gen::<$vec>();

                    let bit_shares = bit.share_with(&mut rng);
                    let a_shares = a.share_with(&mut rng);
                    let b_shares = b.share_with(&mut rng);

                    let futures = zip(context.iter(), zip(bit_shares, zip(a_shares, b_shares)))
                        .map(|(ctx, (bit_share, (a_share, b_share)))| async move {
                            let v = ctx.clone().dzkp_validator(1);
                            let sh_ctx = v.context();

                            let result = select(
                                sh_ctx.set_total_records(1),
                                RecordId::from(0),
                                &bit_share,
                                &a_share,
                                &b_share,
                            )
                            .await?;

                            v.validate().await?;

                            Ok::<_, Error>(result)
                        });

                    let [ab0, ab1, ab2] = join3v(futures).await;

                    let ab = [ab0, ab1, ab2].reconstruct();

                    assert_eq!(ab, if bit.into() { a } else { b });
                }
            }
        }
    };
}

// These macro invocations define the supported vectorization dimensions for `Boolean`.
// The associated BA type must be defined in `ff::boolean_array`.

boolean_vector!(bav_3, 3, BA3);
boolean_vector!(bav_5, 5, BA5);
boolean_vector!(bav_8, 8, BA8);
boolean_vector!(bav_16, 16, BA16);
boolean_vector!(bav_20, 20, BA20);
boolean_vector!(bav_32, 32, BA32);
boolean_vector!(bav_64, 64, BA64);
boolean_vector!(bav_256, 256, BA256);
