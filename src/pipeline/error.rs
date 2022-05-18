use std::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PipelineError {
    #[error("failed to decode message: {0}")]
    DecodeError(#[from] prost::DecodeError),
    #[error("failed to parse message: {0}")]
    ParseError(#[from] std::str::Utf8Error),
    #[error("problem communicating between threads: {0}")]
    ThreadError(Box<dyn std::error::Error + Send + Sync>),
}

impl<T: Debug + Send + Sync + 'static> From<tokio::sync::mpsc::error::SendError<T>>
    for PipelineError
{
    fn from(e: tokio::sync::mpsc::error::SendError<T>) -> Self {
        PipelineError::ThreadError(e.into())
    }
}
impl From<tokio::sync::oneshot::error::RecvError> for PipelineError {
    fn from(e: tokio::sync::oneshot::error::RecvError) -> Self {
        PipelineError::ThreadError(e.into())
    }
}
impl From<tokio::task::JoinError> for PipelineError {
    fn from(e: tokio::task::JoinError) -> Self {
        PipelineError::ThreadError(e.into())
    }
}

pub type Res<T> = Result<T, PipelineError>;
