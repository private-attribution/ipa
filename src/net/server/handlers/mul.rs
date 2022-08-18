use crate::framework::step::Step;
use crate::net::server::MpcServerError;
use axum::extract::Path;

/// handles POST requests of the shape: `/mul/query_id/:query_id/step/:step`
pub async fn handler(Path((query_id, step)): Path<(u32, Step)>) -> Result<(), MpcServerError> {
    println!("{}, {:?}", query_id, step);
    Ok(())
}
