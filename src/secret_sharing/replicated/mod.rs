pub mod malicious;
pub mod semi_honest;

use super::{SecretSharing, SharedValue, WeakSharedValue};

pub trait ReplicatedSecretSharing<V: WeakSharedValue>: SecretSharing<V> {
    fn new(a: V, b: V) -> Self;
    fn left(&self) -> V;
    fn right(&self) -> V;

    fn map<F: Fn(V) -> T, R: ReplicatedSecretSharing<T>, T: SharedValue>(&self, f: F) -> R {
        R::new(f(self.left()), f(self.right()))
    }
}
