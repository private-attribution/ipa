use std::any::type_name;
use std::fmt::Debug;
use std::io;
use std::io::ErrorKind;

use crate::bits::Serializable;
use crate::secret_sharing::ArithmeticShare;

// Trait for primitive integer types used to represent the underlying type for field values
pub trait Int: Sized + Copy + Debug + Into<u128> {
    const BITS: u32;
}

impl Int for u8 {
    const BITS: u32 = u8::BITS;
}

impl Int for u32 {
    const BITS: u32 = u32::BITS;
}

pub trait Field: ArithmeticShare + From<u128> + Into<Self::Integer> {
    type Integer: Int;

    const PRIME: Self::Integer;
    /// Multiplicative identity element
    const ONE: Self;

    /// Blanket implementation to represent the instance of this trait as 16 byte integer.
    /// Uses the fact that such conversion already exists via `Self` -> `Self::Integer` -> `Into<u128>`
    fn as_u128(&self) -> u128 {
        let int: Self::Integer = (*self).into();
        int.into()
    }
}

impl<F: Field> Serializable for F {
    const SIZE_IN_BYTES: usize = ((F::BITS + 7) / 8) as usize;

    /// Generic implementation to serialize fields into a buffer. Callers need to make sure
    /// there is enough capacity to store the value of this field.
    /// It is less efficient because it operates with generic representation of fields as 16 byte
    /// integers, so consider overriding it for actual field implementations
    ///
    /// ## Errors
    /// Returns an error if buffer did not have enough capacity to store this field value
    fn serialize(self, buf: &mut [u8]) -> io::Result<()> {
        let raw_value = &self.as_u128().to_le_bytes()[..<Self as Serializable>::SIZE_IN_BYTES];

        if buf.len() >= raw_value.len() {
            buf[..<Self as Serializable>::SIZE_IN_BYTES].copy_from_slice(raw_value);
            Ok(())
        } else {
            let error_text = format!(
                "Buffer with total capacity {} cannot hold field value {:?} because \
                 it required at least {} bytes available",
                buf.len(),
                self,
                <Self as Serializable>::SIZE_IN_BYTES
            );

            Err(io::Error::new(ErrorKind::WriteZero, error_text))
        }
    }

    /// Generic implementation to deserialize fields from buffer.
    /// It is less efficient because it allocates 16 bytes on the stack to accommodate for all
    /// possible field implementations, so consider overriding it for actual field implementations
    ///
    /// In the bright future when we have const generic expressions, this can be changed to provide
    /// zero-cost generic implementation
    ///
    /// ## Errors
    /// Returns an error if buffer did not have enough capacity left to read the field value.
    fn deserialize(buf_from: &[u8]) -> io::Result<Self> {
        let sz = <Self as Serializable>::SIZE_IN_BYTES;
        if sz <= buf_from.len() {
            let mut buf_to = [0; 16]; // one day...
            buf_to[..sz].copy_from_slice(&buf_from[..sz]);

            Ok(Self::from(u128::from_le_bytes(buf_to)))
        } else {
            let error_text = format!(
                "Buffer is too small to read values of the field type {}. Required at least {sz} bytes,\
                 got {}", type_name::<Self>(), buf_from.len()
            );
            Err(io::Error::new(ErrorKind::UnexpectedEof, error_text))
        }
    }
}
