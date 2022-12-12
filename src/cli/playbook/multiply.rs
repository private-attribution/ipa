use std::fmt::Debug;
use std::marker::PhantomData;
use async_trait::async_trait;
use crate::cli::playbook::{InputSource, Scenario};
use crate::ff::Field;
use crate::secret_sharing::{IntoShares, Replicated};

pub async fn secure_mul<F>(input: &mut InputSource) -> [Vec<impl Send + Debug>; 3]
    where F: Field + IntoShares<Replicated<F>>,
{
    let helper_inputs = input.iter::<(F, F)>().share();
    // TODO: inputs are ready, send them to helpers once query API is ready
    // for now, just print them to make sure sharing works
    helper_inputs
}