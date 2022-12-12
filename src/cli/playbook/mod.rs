mod input;
mod multiply;

use std::fmt::Debug;
use async_trait::async_trait;
pub use input::InputSource;
pub use multiply::secure_mul;


#[async_trait]
pub trait Scenario {
    type Output: Send + Debug;

    async fn execute(&mut self) -> [Vec<Self::Output>; 3];
}


struct Delegated<S> {
    inner: S
}

#[async_trait]
impl <S: Scenario + Send> Scenario for Delegated<S> {
    type Output = S::Output;

    async fn execute(&mut self) -> [Vec<Self::Output>; 3] {
        self.inner.execute().await
    }
}