use crate::error::Error;
use crate::ff::Field;
use crate::protocol::RecordId;
use crate::secret_sharing::SecretSharing;
use async_trait::async_trait;

mod malicious;
mod semi_honest;

#[async_trait]
pub trait RandomBits<F: Field> {
    type Share: SecretSharing<F>;

    async fn generate_random_bits(self, record_id: RecordId) -> Result<Vec<Self::Share>, Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    RandomValues,
    ConvertShares,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::RandomValues => "random_values",
            Self::ConvertShares => "convert_shares",
        }
    }
}
