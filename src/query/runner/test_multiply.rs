use crate::{
    error::Error,
    ff::{Field, FieldType, Fp32BitPrime, Serializable},
    helpers::{ByteArrStream, TotalRecords},
    protocol::{
        basics::SecureMul,
        context::{Context, SemiHonestContext},
        RecordId,
    },
    query::ProtocolResult,
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};
use futures_util::StreamExt;
use typenum::Unsigned;

pub struct Runner;

impl Runner {
    pub async fn run(
        &self,
        ctx: SemiHonestContext<'_>,
        field: FieldType,
        input: ByteArrStream,
    ) -> Box<dyn ProtocolResult> {
        match field {
            #[cfg(any(test, feature = "weak-field"))]
            FieldType::Fp31 => Box::new(
                self.run_internal::<crate::ff::Fp31>(ctx, input)
                    .await
                    .unwrap(),
            ),
            FieldType::Fp32BitPrime => {
                Box::new(self.run_internal::<Fp32BitPrime>(ctx, input).await.unwrap())
            }
        }
    }

    async fn run_internal<F: Field>(
        &self,
        ctx: SemiHonestContext<'_>,
        input: ByteArrStream,
    ) -> std::result::Result<Vec<Replicated<F>>, Error>
    where
        Replicated<F>: Serializable,
    {
        let ctx = ctx.set_total_records(TotalRecords::Indeterminate);

        let mut input = input.align(<Replicated<F> as Serializable>::Size::USIZE);
        let mut results = Vec::new();
        while let Some(v) = input.next().await {
            // multiply pairs
            let mut a = None;
            let mut record_id = 0_u32;
            for share in Replicated::<F>::from_byte_slice(&v.unwrap()) {
                match a {
                    None => a = Some(share),
                    Some(a_v) => {
                        let result = a_v
                            .multiply(&share, ctx.clone(), RecordId::from(record_id))
                            .await
                            .unwrap();
                        results.push(result);
                        record_id += 1;
                        a = None;
                    }
                }
            }

            assert!(a.is_none());
        }

        Ok(results)
    }
}

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
mod tests {
    use super::*;
    use crate::{
        ff::Fp31,
        secret_sharing::IntoShares,
        test_fixture::{join3v, Reconstruct, TestWorld},
    };
    use generic_array::GenericArray;
    use typenum::Unsigned;

    #[tokio::test]
    async fn multiply() {
        let world = TestWorld::default();
        let contexts = world.contexts();
        let a = [Fp31::truncate_from(4u128), Fp31::truncate_from(5u128)];
        let b = [Fp31::truncate_from(3u128), Fp31::truncate_from(6u128)];

        let helper_shares = (a, b).share().map(|(a, b)| {
            const SIZE: usize = <Replicated<Fp31> as Serializable>::Size::USIZE;
            let r = a
                .into_iter()
                .zip(b)
                .flat_map(|(a, b)| {
                    let mut slice = [0_u8; 2 * SIZE];
                    a.serialize(GenericArray::from_mut_slice(&mut slice[..SIZE]));
                    b.serialize(GenericArray::from_mut_slice(&mut slice[SIZE..]));

                    slice
                })
                .collect::<Vec<_>>();

            ByteArrStream::from(r)
        });

        let results = join3v(
            helper_shares
                .into_iter()
                .zip(contexts)
                .map(|(shares, context)| Runner.run_internal::<Fp31>(context, shares)),
        )
        .await;

        let results = results.reconstruct();

        assert_eq!(
            vec![Fp31::truncate_from(12u128), Fp31::truncate_from(30u128)],
            results
        );
    }
}
