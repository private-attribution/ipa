use crate::{
    error::Error,
    ff::{ec_prime_field::Fp25519, curve_points::RP25519},
    protocol::{context::Context, RecordId, prss::SharedRandomness, basics::Reveal, basics::SecureMul},
    secret_sharing::{replicated::{semi_honest::AdditiveShare,ReplicatedSecretSharing}},
};


impl From<AdditiveShare<Fp25519>> for AdditiveShare<RP25519> {
    fn from(s: AdditiveShare<Fp25519>) -> Self {
        AdditiveShare::new(RP25519::from(s.left()),RP25519::from(s.right()))
    }
}

/// generates PRF key k as secret sharing over Fp25519
pub fn gen_prf_key<C> (ctx: C) -> AdditiveShare<Fp25519>
    where
        C: Context,
{
    ctx.prss().generate_replicated(u128::MAX-100u128)
}


/// evaluates the Dodis-Yampolski PRF g^(1/(k+x))
/// the input x and k are secret shared over finite field Fp25519, i.e. the scalar field of curve 25519
/// PRF key k is generated using keygen
/// In 3IPA, x is the match key
/// eval_DY outputs a u64 as specified in protocol/prf_sharding/mod.rs, all parties learn the output
pub async fn eval_dy_prf<C, S>(
    ctx: C,
    record_id: RecordId,
    k: &AdditiveShare<Fp25519>,
    x: &AdditiveShare<Fp25519>,
) -> Result<u64, Error>
    where
        C: Context,
{
    // generate random shares using shared randomness, use index max/2 to not clash with multiply
    let sh_r: AdditiveShare<Fp25519> = ctx.prss().generate_replicated(u128::MAX/2+u128::from(record_id));

    //compute (g^left, g^right)
    let sh_gr = AdditiveShare::<RP25519>::from(sh_r.clone());

    //compute x+k
    let y =x+k;

    //compute y <- r*y
    //Daniel: probably shouldn't use ctx anymore? why doesn't y need to be mutable?
    y.multiply(&sh_r, ctx.clone(), record_id).await?;

    //reconstruct (z,R)
    let mut gr: RP25519 = sh_gr.reveal(ctx, record_id).await?;

    //invert z
    let mut z: Fp25519 = Fp25519::ONE;
    z=z.invert();
    //compute R^z
    gr=gr.s_mul(z);
    Ok(u64::from(gr))
}

#[cfg(all(test, unit_test))]
mod test {

}