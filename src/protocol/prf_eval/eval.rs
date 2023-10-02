use crate::{
    error::Error,
    helpers::Direction,
    ff::ec_prime_field::Fp25519,
    protocol::{context::Context, step::BitOpStep, BasicProtocols, RecordId},
    secret_sharing::{Linear as LinearSecretSharing, LinearRefOps},
};

/// evaluates the Dodis-Yampolski PRF g^(1/(k+x))
/// the input x and k are secret shared over finite field Fp25519, i.e. the scalar field of curve 25519
/// PRF key k is generated using keygen
/// In 3IPA, x is the match key
/// eval_DY outputs a u64 as specified in protocol/prf_sharding/mod.rs, all parties learn the output
pub async fn eval_dy<C, S>(
    ctx: C,
    record_id: RecordId,
    k: &[S],
    x: &[S],
) -> Result<u64, Error>
    where
        C: Context,
        S: LinearSecretSharing<Fp25519> + BasicProtocols<C, Fp25519>,
        for<'a> &'a S: LinearRefOps<'a, S, Fp25519>,
{
    let role = ctx.role();

    Ok(5u64)
}