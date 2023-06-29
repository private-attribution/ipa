pub mod malicious;
pub mod semi_honest;

use super::{SecretSharing, SharedValue};

pub trait ReplicatedSecretSharing<V: SharedValue>: SecretSharing<V> {
    fn new(a: V, b: V) -> Self;
    fn left(&self) -> V;
    fn right(&self) -> V;
}
