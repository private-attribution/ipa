use crate::cli::playbook::InputSource;
use crate::ff::Field;
use crate::secret_sharing::{IntoShares, Replicated};
use std::fmt::Debug;

/// Secure multiplication. Each input must be a valid tuple of field values.
/// `(a, b)` will produce `a` * `b`.
#[allow(clippy::unused_async)] // soon it will be used
pub async fn secure_mul<F>(input: InputSource) -> [Vec<impl Send + Debug>; 3]
where
    F: Field + IntoShares<Replicated<F>>,
{
    // TODO: inputs are ready, send them to helpers once query API is ready
    // for now, just print them to make sure sharing works
    input.iter::<(F, F)>().share()
}
