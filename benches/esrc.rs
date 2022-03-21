//! benchmarks are still experimental in rust, so will only compile with the nightly compiler.
//! In order to run this benchmark:
//! * install nightly compiler
//!   ```sh
//!   rustup toolchain install nightly
//!   ```
//! * compile and benchmark using nightly compiler
//!   ```sh
//!   rustup run nightly cargo bench
//!   ```

#![feature(test)]

extern crate test;

use bls12_381::{G1Affine, Scalar};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use raw_ipa::esrc;
use test::Bencher;

#[bench]
// running on a 2021 MBP 14":
// test bench_enc_randomize_verify ... bench:  19,898,745 ns/iter (+/- 471,474)
// aka about 20ms
fn bench_enc_randomize_verify(b: &mut Bencher) {
    let mut rng = StdRng::from_entropy();
    let e = esrc::Esrc::new(&mut rng);

    b.iter(|| {
        // message to send
        let m = G1Affine::from(G1Affine::generator() * Scalar::from(rng.next_u64()));

        // initial encryption and signing
        let cm = e.encrypt(&mut rng, m);
        let signature = e.sign(&mut rng, &cm);

        // rerandomize
        let r_prime = Scalar::from(rng.next_u64());
        let r_cm = e.randomize(&cm, r_prime);
        let r_signature = e.adapt(&mut rng, &signature, r_prime);

        // verify
        assert!(e.verify(&r_cm, &r_signature));
    });
}
