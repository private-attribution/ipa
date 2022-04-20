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
//! Lastly, using `u128` as a backing field to store shared secrets is too optimistic - a larger
//! type is required to store secrets.
//!
//!
//! [Paper] - <https://eprint.iacr.org/2019/1390.pdf>

use hkdf::Hkdf;
use rand::distributions::{Distribution, Standard};
use rand::{thread_rng, Rng};
use sha2::Sha256;

/// Represents a secret in the system that must obey the following properties:
/// - addition
/// - multiplication
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct SharedSecret(u128);

impl From<u128> for SharedSecret {
    fn from(v: u128) -> Self {
        SharedSecret(v)
    }
}

impl SharedSecret {
    /// Adds a given shared secret and returns a new instance
    ///
    /// ```
    /// use raw_ipa::shmc::SharedSecret;
    /// let u = SharedSecret::from(5);
    /// let v = SharedSecret::from(10);
    ///
    /// assert_eq!(SharedSecret::from(15), u.wrapping_add(v));
    /// ```
    #[must_use]
    pub fn wrapping_add(self, other: Self) -> Self {
        SharedSecret(self.0.wrapping_add(other.0))
    }

    /// Subtracts a given shared secret and returns a new instance
    ///
    /// ```
    /// use raw_ipa::shmc::SharedSecret;
    /// let u = SharedSecret::from(3);
    /// let v = SharedSecret::from(10);
    ///
    /// assert_eq!(SharedSecret::from(7), v.wrapping_sub(u));
    /// ```
    #[must_use]
    pub fn wrapping_sub(self, other: Self) -> Self {
        SharedSecret(self.0.wrapping_sub(other.0))
    }

    /// Multiplies by a given shared secret and returns a new instance
    ///
    /// ```
    /// use raw_ipa::shmc::SharedSecret;
    /// let u = SharedSecret::from(7);
    /// let v = SharedSecret::from(11);
    ///
    /// assert_eq!(SharedSecret::from(77), v.wrapping_mul(u));
    /// ```
    #[must_use]
    pub fn wrapping_mul(self, other: Self) -> Self {
        SharedSecret(self.0.wrapping_mul(other.0))
    }

    /// Shares this secret to 3 parties by choosing three random elements (v1..v3)
    /// under the constraint that v1+v2+v3 == self
    #[must_use]
    pub fn share(&self) -> [Share; 3] {
        // thread_rng() is secure, but may not be secure enough for us. need to check
        // what rand crate uses for it.
        let u1 = thread_rng().gen::<Self>();
        let u2 = thread_rng().gen::<Self>();
        let u3 = self.wrapping_sub(u1.wrapping_add(u2));

        [Share(u1, u3), Share(u2, u1), Share(u3, u2)]
    }

    /// Assembles a new `SharedSecret` from the given shares.
    ///
    /// Example:
    /// ```
    /// use raw_ipa::shmc::SharedSecret;
    ///
    /// let s = SharedSecret::from(5);
    /// assert_eq!(s, SharedSecret::from_shares(s.share()));
    /// ```
    #[must_use]
    pub fn from_shares(shares: [Share; 3]) -> Self {
        let u1 = shares[0].0;
        let u2 = shares[1].0;
        let u3 = shares[2].0;

        u1.wrapping_add(u2).wrapping_add(u3)
    }

    /// Computes KDF over this secret with a given seed.
    #[must_use]
    pub(crate) fn kdf(&self, seed: u64) -> Self {
        // require thorough security review
        let prf: Hkdf<Sha256> = Hkdf::new(None, &seed.to_be_bytes());
        let mut output = [0u8; 16];
        prf.expand(&self.0.to_be_bytes(), &mut output)
            .expect("Failed to expand HKDF");

        Self(u128::from_be_bytes(output))
    }
}

impl Distribution<SharedSecret> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SharedSecret {
        let v = rng.gen();

        SharedSecret(v)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Randomness {
    share: Share,
    seed: u64,
}

/// A share of `SharedSecret`.
#[derive(Copy, Clone, Debug)]
pub struct Share(SharedSecret, SharedSecret);

impl Share {
    /// Computes HKDF over this share and returns a new instance of `SharedSecret`.
    #[must_use]
    pub fn kdf(&self, seed: u64) -> SharedSecret {
        self.0.kdf(seed).wrapping_sub(self.1.kdf(seed))
    }

    /// Multiplies two shares with a given randomness and returns a new instance of `SharedSecret`.
    /// if `(u0, u1)` and `(v0, v1)` are two shares and `a` is randomness,
    /// then the product is defined as `u0`*`v0` + `u0`*`v1` + `u1`*`v0` + `a`.
    #[must_use]
    pub fn wrapping_mul(self, other: Share, rand: Randomness) -> SharedSecret {
        self.0
            .wrapping_mul(other.0)
            .wrapping_add(self.0.wrapping_mul(other.1))
            .wrapping_add(self.1.wrapping_mul(other.0))
            .wrapping_add(rand.share.kdf(rand.seed))
    }
}

#[cfg(test)]
mod shared_secret_tests {
    use crate::shmc::SharedSecret;

    #[test]
    pub fn share() {
        fn verify(v: u128) {
            let secret = SharedSecret(v);
            assert_eq!(secret, SharedSecret::from_shares(secret.share()));
        }

        verify(0);
        verify(1);
        verify(u128::MAX);
    }

    #[test]
    pub fn mul() {
        assert_eq!(
            SharedSecret(9),
            SharedSecret(3).wrapping_mul(SharedSecret(3))
        );
        assert_eq!(
            SharedSecret(0),
            SharedSecret(3).wrapping_mul(SharedSecret(0))
        );
        assert_eq!(
            SharedSecret(u128::MAX - 3),
            SharedSecret(u128::MAX - 1).wrapping_mul(SharedSecret(2))
        );
    }

    #[test]
    pub fn kdf() {
        assert_eq!(SharedSecret(5).kdf(10), SharedSecret(5).kdf(10));
        assert_ne!(SharedSecret(5).kdf(10), SharedSecret(6).kdf(10));
        assert_ne!(SharedSecret(5).kdf(10), SharedSecret(5).kdf(11));
    }
}

#[cfg(test)]
mod share_tests {
    use crate::shmc::{Randomness, SharedSecret};

    #[test]
    pub fn mul() {
        let u_shares = SharedSecret(5).share();
        let v_shares = SharedSecret(10).share();
        let randomness = SharedSecret(10_202_002).share().map(|s| Randomness {
            share: s,
            seed: 123,
        });

        let actual = u_shares
            .iter()
            .enumerate()
            .map(|(i, u)| u.wrapping_mul(v_shares[i], randomness[i]))
            .fold(SharedSecret(0), SharedSecret::wrapping_add);

        assert_eq!(SharedSecret(50), actual);
    }
}

#[allow(dead_code)]
mod helper {
    use crate::shmc::{Randomness, Share, SharedSecret};
    use std::sync::mpsc;
    use std::sync::mpsc::{Receiver, Sender};
    use std::thread;
    use std::thread::JoinHandle;

    pub type Next = Sender<Command>;

    /// Messages that are accepted and understood by the helper process.
    #[derive(Debug)]
    pub enum Command {
        SetNext(Next),
        SetMultiplier(Share),
        SetMultiplicand(Share, Randomness),
        PeerSecret(SharedSecret),
    }

    pub enum Message {
        MulComplete(SharedSecret),
    }

    pub struct Helper {
        _process: JoinHandle<()>,
        pub output: Receiver<Message>,
    }

    #[derive(Debug, Default)]
    struct HelperState {
        next: Option<Next>,
        multiplier: Option<Share>,
        multiplicand: (Option<Share>, Option<Randomness>),
        peer_secret: Option<SharedSecret>,
        result: Option<SharedSecret>,
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

        pub fn set_peer_secret(&mut self, v: SharedSecret) {
            self.peer_secret.get_or_insert(v);
        }

        pub fn compute(&mut self) -> Option<SharedSecret> {
            // This state indicates that helper is ready to perform multiplication
            // and it hasn't done it yet
            if let HelperState {
                multiplier: Some(mr),
                multiplicand: (Some(md), Some(r)),
                result: None,
                ..
            } = self
            {
                self.result = Some(mr.wrapping_mul(*md, *r));
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
    use crate::shmc::helper::{Command, Helper, Message, Next};
    use crate::shmc::{Randomness, Share, SharedSecret};
    use rand::{thread_rng, Rng};
    use std::sync::mpsc;
    use std::sync::mpsc::RecvError;

    struct HelperClient {
        helper: Helper,
        tx: Next,
        mul_result: Option<SharedSecret>,
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
        pub fn get_product(&self) -> SharedSecret {
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
        let mut helper_clients: Vec<_> = (0..=2).map(|_| HelperClient::new()).collect();
        let secret_u = SharedSecret(3);
        let secret_v = SharedSecret(6);
        let expected = secret_u.wrapping_mul(secret_v);

        init_helpers(helper_clients.as_slice(), secret_u);

        let result = multiply_by(helper_clients.as_mut_slice(), secret_v, 6).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn computes_two_shares() {
        let mut helper_clients: Vec<_> = (0..=2).map(|_| HelperClient::new()).collect();

        let secret_u = SharedSecret(3);
        let secret_v = SharedSecret(6);
        let secret_w = SharedSecret(5);
        // expect 90=3*6*5
        let expected = secret_u.wrapping_mul(secret_v).wrapping_mul(secret_w);

        init_helpers(helper_clients.as_slice(), secret_u);
        multiply_by(helper_clients.as_mut_slice(), secret_v, 6).unwrap();
        let result = multiply_by(helper_clients.as_mut_slice(), secret_w, 6).unwrap();

        assert_eq!(result, expected);
    }

    fn init_helpers(helpers: &[HelperClient], multiplier: SharedSecret) {
        connect_helpers(helpers);
        let multiplier = multiplier.share();
        for (i, client) in helpers.iter().enumerate() {
            client.send_multiplier(multiplier[i]);
        }
    }

    fn connect_helpers(helpers: &[HelperClient]) {
        assert_eq!(helpers.len(), 3);

        let mut i = 1;
        while i < helpers.len() {
            helpers[i - 1].set_next(&helpers[i]);
            i += 1;
        }

        helpers[i - 1].set_next(&helpers[0]);
    }

    fn multiply_by(
        helpers: &mut [HelperClient],
        multiplicand: SharedSecret,
        seed: u64,
    ) -> Result<SharedSecret, RecvError> {
        let mul_shares = multiplicand.share();
        let randomness = thread_rng().gen::<SharedSecret>().share();

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
            .fold(SharedSecret(0), |acc, x| x.get_product().wrapping_add(acc));

        Ok(result)
    }
}
