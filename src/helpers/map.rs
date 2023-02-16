/// Trait for transforming values in the manner of `Option::map` or `Iter::map`.
///
/// This is currently used to implement [malicious downgrades], and can be used to
/// generically implement other operations in the future.
///
/// The type parameter `M` represents the mapping being performed. It is analogous to the `F`
/// closure type parameter on `Option::map`.
///
/// [malicious downgrades]: crate::secret_sharing::replicated::malicious::UncheckedDowngrade
pub trait Map<M: Mapping> {
    type Output;

    fn map(self) -> Self::Output;
}

pub trait Mapping {}

impl<T, U, M: Mapping> Map<M> for (T, U)
where
    T: Map<M>,
    U: Map<M>,
{
    type Output = (<T as Map<M>>::Output, <U as Map<M>>::Output);
    fn map(self) -> Self::Output {
        (self.0.map(), self.1.map())
    }
}

impl<T, M: Mapping> Map<M> for Vec<T>
where
    T: Map<M>,
{
    type Output = Vec<<T as Map<M>>::Output>;
    fn map(self) -> Self::Output {
        self.into_iter().map(<T as Map<M>>::map).collect()
    }
}
