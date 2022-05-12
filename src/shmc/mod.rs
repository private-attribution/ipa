//!
//! Semi-honest multiplication protocol
//!
//! This module provides a naive implementation of semi-honest multiplication protocol ([Paper])
//! (section 2.1.1). IPA protocol defines 3 parties (helpers)
//! as participants in this protocol, this implementation assumes there will be exactly 3 instances
//! to compute the result.
//!
//! - [Helper](helper::Helper) represents a party in the protocol, assuming at most one out of 3
//! may be compromised. Helper state can be changed by sending [`HelperCommand`](helper::HelperCommand)
//! to it. When helper computes 3/2 shares, it broadcasts [`HelperMessage`](helper::HelperMessage)
//! with the result of the computation.
//!
//! The current implementation allows commands to arrive out-of-order, multiplication will be
//! performed when all the required information is gathered by an individual helper. When helper
//! has computed its own share, it awaits the next argument (multiplicand) to perform the multiplication
//! again.
//!
//! ## Correlated randomness
//!
//! This module steps away from the "canonical" correlated randomness implementation described in
//! the [Paper] for efficiency reasons and, instead, requires requester to provide random share and
//! seed along with the multiplicand to each helper. This reduces the total number of communication
//! each helper has to perform before computing multiplication.
//!
//! ## Remarks
//!
//! There are a couple of well-known issues with this implementation. Firstly, the protocol does not
//! have any notion of a round of computation: given the secrets `u` and `v`, every message related
//! to multiplying `u` and `v` must be clearly distinguishable from any other message that is not
//! related to `u` and `v`. It is possible to achieve by generating a unique identifier for every
//! multiplication round and annotating messages that carry `u` or `v` information with it.
//! Secondly, message processing and computation is done in the same thread and this implementation
//! does not use async model which may be beneficial here for performance reasons.
//!
//! [Paper] - <https://eprint.iacr.org/2019/1390.pdf>

use std::fmt::{Display, Formatter};
use std::ops::{Add, Mul, Sub};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use rust_elgamal::Scalar;
use sha2::Sha256;
use crate::error::Res;

#[derive(Debug, Copy, Clone)]
pub struct Randomness {
    share: Share,
    seed: Scalar,
}

/// A share of `Scalar`.
#[derive(Copy, Clone, Debug)]
pub struct Share(Scalar, Scalar);

#[derive(Debug)]
pub enum ShareError {
    ReconstructionFailed([Share; 3])
}

impl Display for ShareError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ShareError::ReconstructionFailed(_) => {
                f.write_str("Share reconstruction failed")
            }
        }
    }
}

impl std::error::Error for ShareError { }

trait ShareComposite: Add + Sub + Sized {
    /// Splits self into 3 shares by choosing three random elements (v1..v3)
    /// under the constraint that v1+v2+v3 == Self
    fn share<R: RngCore + CryptoRng>(&self, rng: &mut R) -> [Share; 3];

    /// Assembles a new instance from the given shares.
    fn from_shares(inp: [Share; 3]) -> Res<Self>;
}

trait Kdf {
    type Output;
    fn kdf(&self, seed: Self::Output) -> Self::Output;
}

impl Kdf for Scalar {
    type Output = Scalar;

    fn kdf(&self, seed: Self::Output) -> Self::Output {
        let prf: Hkdf<Sha256> = Hkdf::new(None, seed.as_bytes());

        let mut output = [0u8; 32];
        prf.expand(self.as_bytes(), &mut output)
            .expect("Failed to expand HDKF");

        Scalar::from_bits(output)
    }
}


impl ShareComposite for Scalar {
    #[must_use]
    fn share<R: RngCore + CryptoRng>(&self, rng: &mut R) -> [Share; 3] {
        let u1 = Scalar::random(rng);
        let u2 = Scalar::random(rng);
        let u3 = self.sub(u1.add(u2));

        [Share(u1, u3), Share(u2, u1), Share(u3, u2)]
    }

    #[must_use]
    fn from_shares(shares: [Share; 3]) -> Res<Self> {
        let u1 = shares[0].0;
        let u2 = shares[1].0;
        let u3 = shares[2].0;

        if u1 != shares[1].1 || u2 != shares[2].1 || u3 != shares[0].1 {
            Err(ShareError::ReconstructionFailed(shares).into())
        } else {
            Ok(u1.add(u2).add(u3))
        }

    }
}

impl Share {
    /// Multiplies two shares with a given randomness and returns a new instance of `Scalar`.
    /// if `(u0, u1)` and `(v0, v1)` are two shares and `a` is randomness,
    /// then the product is defined as `u0`*`v0` + `u0`*`v1` + `u1`*`v0` + `a`.
    #[must_use]
    pub fn mul(self, other: Share, rand: Randomness) -> Scalar {
        self.0
            .mul(other.0)
            .add(self.0.mul(other.1))
            .add(self.1.mul(other.0))
            .add(rand.share.0.kdf(rand.seed))
            .sub(rand.share.1.kdf(rand.seed))
    }
}

#[cfg(test)]
mod scalar_composite_tests {
    use std::ops::{Add, AddAssign, Mul};
    use rand::rngs::StdRng;
    use rand::thread_rng;
    use rand_core::SeedableRng;
    use rust_elgamal::Scalar;
    use crate::error::Error::SemiHonestProtocolError;
    use crate::shmc::{ShareComposite, ShareError};

    #[test]
    pub fn works() {
        fn verify(v: u128) {
            let mut rng = StdRng::seed_from_u64(1);
            let scalar_v = Scalar::from(v);
            let shares = scalar_v.share(&mut rng);
            assert_eq!(scalar_v, Scalar::from_shares(shares.clone()).unwrap());

            // summing up shares yields the initial value * 2
            assert_eq!(scalar_v.mul(Scalar::from(2_u32)), shares.iter()
                .fold(Scalar::zero(), |acc, share| acc.add(share.0).add(share.1)));
        }

        verify(0);
        verify(1);
        verify(u128::MAX);
    }

    #[test]
    pub fn uses_rng() {
        let mut rng = StdRng::seed_from_u64(1);
        let scalar = Scalar::from(1_u64);
        let shares = scalar.share(&mut rng);

        for share in &shares {
            assert_ne!(share.0, share.1)
        }
    }

    #[test]
    pub fn reconstruction_is_fallible() {
        let scalar_v = Scalar::from(5_u32);
        let mut shares = scalar_v.share(&mut thread_rng());
        shares[0].1.add_assign(Scalar::from(1_u32));
        assert!(matches!(Scalar::from_shares(shares), Err(SemiHonestProtocolError(ShareError::ReconstructionFailed(_)))))
    }
}

#[cfg(test)]
mod share_tests {
    use std::ops::Add;
    use rand::thread_rng;
    use rust_elgamal::Scalar;
    use crate::shmc::{Kdf, Randomness, ShareComposite};

    #[test]
    pub fn mul() {
        let u_shares = Scalar::from(5_u32).share(&mut thread_rng());
        let v_shares = Scalar::from(10_u32).share(&mut thread_rng());
        let randomness = Scalar::from(10_202_002_u32).share(&mut thread_rng())
            .map(|s| Randomness {
                share: s,
                seed: Scalar::from(123_u32),
            });

        let actual = u_shares
            .iter()
            .enumerate()
            .map(|(i, u)| u.mul(v_shares[i], randomness[i]))
            .fold(Scalar::zero(), Scalar::add);

        assert_eq!(Scalar::from(50_u32), actual);
    }

    #[test]
    pub fn kdf() {
        let seed = Scalar::from(10_u32);
        let another_seed = seed.add(Scalar::from(2_u32));
        assert_eq!(Scalar::from(5_u32).kdf(seed), Scalar::from(5_u32).kdf(seed));
        assert_ne!(Scalar::from(5_u32).kdf(seed), Scalar::from(6_u32).kdf(seed));
        assert_ne!(Scalar::from(5_u32).kdf(seed), Scalar::from(5_u32).kdf(another_seed));
    }
}

#[allow(dead_code)]
mod helper {
    use crate::shmc::{Randomness, Share};
    use std::sync::mpsc;
    use std::sync::mpsc::{Receiver, Sender};
    use std::thread;
    use std::thread::JoinHandle;
    use rust_elgamal::Scalar;

    pub type Next = Sender<Command>;

    /// Messages that are accepted and understood by the helper process.
    #[derive(Debug)]
    pub enum Command {
        SetNext(Next),
        SetMultiplier(Share),
        SetMultiplicand(Share, Randomness),
        PeerSecret(Scalar),
    }

    pub enum Message {
        MulComplete(Scalar),
    }

    #[derive(Debug)]
    pub struct Helper {
        _process: JoinHandle<()>,
        pub output: Receiver<Message>,
    }

    #[derive(Debug, Default)]
    struct HelperState {
        next: Option<Next>,
        multiplier: Option<Share>,
        multiplicand: (Option<Share>, Option<Randomness>),
        peer_secret: Option<Scalar>,
        result: Option<Scalar>,
        peer_notified: bool,
    }

    impl HelperState {
        pub fn set_next(&mut self, next: Next) {
            self.next.get_or_insert(next);
        }
        pub fn set_multiplier(&mut self, s: Share) {
            self.multiplier.get_or_insert(s);
        }

        pub fn set_multiplicand(&mut self, s: Share, r: Randomness) {
            if let (None, None) = self.multiplicand {
                self.multiplicand = (Some(s), Some(r));
            }
        }

        pub fn set_peer_secret(&mut self, v: Scalar) {
            self.peer_secret.get_or_insert(v);
        }

        pub fn compute(&mut self) -> Option<Scalar> {
            // This state indicates that helper is ready to perform multiplication
            // and it hasn't done it yet
            if let HelperState {
                multiplier: Some(mr),
                multiplicand: (Some(md), Some(r)),
                result: None,
                ..
            } = self
            {
                self.result = Some(mr.mul(*md, *r));
            }

            // If helper carries the result of the multiplication but hasn't notified the peer
            // yet, do it now
            if let HelperState {
                next: Some(next),
                result: Some(r),
                peer_notified: false,
                ..
            } = self
            {
                next.send(Command::PeerSecret(*r))
                    .expect("Failed to notify next helper");
                self.peer_notified = true;
            }

            // when multiplication, notify next steps are completed and peer share is received
            // helper is ready to perform another multiplication
            if let HelperState {
                result: Some(r),
                peer_notified: true,
                peer_secret: Some(p),
                ..
            } = self
            {
                self.multiplier = Some(Share(*r, *p));
                self.multiplicand = (None, None);
                self.peer_secret = None;
                self.peer_notified = false;

                self.result.take()
            } else {
                None
            }
        }
    }

    fn event_loop(state: &mut HelperState, rx: Receiver<Command>, publish: &Sender<Message>) {
        for msg in rx {
            match msg {
                Command::SetNext(next) => state.set_next(next),
                Command::SetMultiplier(share) => state.set_multiplier(share),
                Command::SetMultiplicand(share, rand) => state.set_multiplicand(share, rand),
                Command::PeerSecret(peer_secret) => state.set_peer_secret(peer_secret),
            }

            if let Some(product) = state.compute() {
                publish
                    .send(Message::MulComplete(product))
                    .expect("Failed to send the result of the multiplication");
            }
        }
    }

    impl Helper {
        pub fn new(rx: Receiver<Command>) -> Helper {
            let (publish_tx, publish_rx) = mpsc::channel();
            let mut state = HelperState::default();

            let thread = thread::spawn(move || event_loop(&mut state, rx, &publish_tx));

            Helper {
                _process: thread,
                output: publish_rx,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::{Add, Mul};
    use crate::shmc::helper::{Command, Helper, Message, Next};
    use crate::shmc::{Randomness, Share, ShareComposite};
    use rand::{thread_rng};
    use std::sync::mpsc;
    use std::sync::mpsc::RecvError;
    use rust_elgamal::Scalar;

    #[derive(Debug)]
    struct HelperClient {
        helper: Helper,
        tx: Next,
        mul_result: Option<Scalar>,
    }

    impl HelperClient {
        pub fn new() -> HelperClient {
            let (tx, rx) = mpsc::channel();
            let helper = Helper::new(rx);
            HelperClient {
                helper,
                tx,
                mul_result: None,
            }
        }

        pub fn send_multiplier(&self, share: Share) {
            self.tx.send(Command::SetMultiplier(share)).unwrap();
        }
        pub fn send_multiplicand(&self, share: Share, rand: Randomness) {
            self.tx.send(Command::SetMultiplicand(share, rand)).unwrap();
        }
        pub fn get_product(&self) -> Scalar {
            self.mul_result.expect("Multiplier hasn't been set")
        }

        pub fn set_next(&self, next: &HelperClient) {
            self.tx.send(Command::SetNext(next.tx.clone())).unwrap();
        }

        pub fn await_mul(&mut self) -> Result<(), RecvError> {
            let Message::MulComplete(share) = self.helper.output.recv()?;
            self.mul_result = Some(share);
            Ok(())
        }
    }

    #[test]
    fn computes_shares() {
        let mut helper_clients = make_helpers();

        let secret_u = Scalar::from(3_u64);
        let secret_v = Scalar::from(6_u64);
        let seed = Scalar::from(9_u64);
        let expected = secret_u.mul(secret_v);

        init_helpers(&helper_clients, secret_u);

        let result = multiply_by(&mut helper_clients, secret_v, seed).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn computes_two_shares() {
        let mut helper_clients = make_helpers();

        let secret_u = Scalar::from(3_u32);
        let secret_v = Scalar::from(6_u32);
        let secret_w = Scalar::from(5_u32);
        let seed = Scalar::from(9_u64);
        // expect 90=3*6*5
        let expected = secret_u.mul(secret_v).mul(secret_w);

        init_helpers(&helper_clients, secret_u);
        multiply_by(&mut helper_clients, secret_v, seed).unwrap();
        let result = multiply_by(&mut helper_clients, secret_w, seed).unwrap();

        assert_eq!(result, expected);
    }

    fn make_helpers() -> [HelperClient; 3] {
        (0..=2).map(|_| HelperClient::new())
            .collect::<Vec<_>>()
            .try_into()
            .expect("Failed to create exactly 3 helpers")
    }

    fn init_helpers(helpers: &[HelperClient; 3], multiplier: Scalar) {
        connect_helpers(helpers);
        let multiplier = multiplier.share(&mut thread_rng());
        for (i, client) in helpers.iter().enumerate() {
            client.send_multiplier(multiplier[i]);
        }
    }

    fn connect_helpers(helpers: &[HelperClient; 3]) {
        helpers[0].set_next(&helpers[1]);
        helpers[1].set_next(&helpers[2]);
        helpers[2].set_next(&helpers[0]);
    }

    fn multiply_by(
        helpers: &mut [HelperClient; 3],
        multiplicand: Scalar,
        seed: Scalar,
    ) -> Result<Scalar, RecvError> {
        let mut rng = thread_rng();
        let mul_shares = multiplicand.share(&mut rng);
        let randomness = Scalar::random(&mut rng).share(&mut rng);

        assert_eq!(helpers.len(), mul_shares.len());

        for (i, client) in helpers.iter().enumerate() {
            client.send_multiplicand(
                mul_shares[i],
                Randomness {
                    share: randomness[i],
                    seed,
                },
            );
        }

        for client in helpers.iter_mut() {
            client.await_mul()?;
        }

        let result = helpers
            .iter()
            .fold(Scalar::zero(), |acc, x| x.get_product().add(acc));

        Ok(result)
    }
}
