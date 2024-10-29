pub mod malicious;
pub mod semi_honest;

use super::{SecretSharing, SharedValue};
use crate::helpers::Direction;

pub trait ReplicatedSecretSharing<V: SharedValue>: SecretSharing<V> {
    fn new(a: V, b: V) -> Self;
    fn left(&self) -> V;
    fn right(&self) -> V;

    fn new_excluding_direction(v: V, direction: Direction) -> Self {
        match direction {
            Direction::Left => Self::new(V::ZERO, v),
            Direction::Right => Self::new(v, V::ZERO),
        }
    }

    fn map<F: Fn(V) -> T, R: ReplicatedSecretSharing<T>, T: SharedValue>(&self, f: F) -> R {
        R::new(f(self.left()), f(self.right()))
    }
}
