#![feature(test)]
#![allow(soft_unstable)]

extern crate test;

use bls12_381::{G1Affine, Scalar};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use raw_ipa::esrc;
use test::Bencher;

#[bench]
fn bench_enc_randomize_verify(b: &mut Bencher) {
    let mut rng = StdRng::from_entropy();
    let (enc_key, _dec_key) = esrc::setup_encryption_keys(&mut rng);
    let (sign_key, verify_key) = esrc::setup_signing_keys(&mut rng);

    b.iter(|| {
        // message to send
        let m = G1Affine::from(G1Affine::generator() * Scalar::from(rng.next_u64()));

        // initial encryption and signing
        let enc_m = esrc::encrypt(&mut rng, m, &enc_key);
        let signature = esrc::sign(&mut rng, &enc_m, &enc_key, sign_key);

        // rerandomize
        let r_prime = Scalar::from(rng.next_u64());
        let r_enc_m = esrc::randomize(&enc_m, &enc_key, r_prime);
        let r_signature = esrc::adapt(&mut rng, &signature, r_prime);

        // verify
        assert!(esrc::verify(&verify_key, &enc_key, &r_enc_m, &r_signature));
    });
}
