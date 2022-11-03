use std::any::type_name;
use std::fmt::Debug;
use std::io;
use std::io::ErrorKind;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Mul, MulAssign,
    Neg, Not, Shr, Sub, SubAssign,
};

// Trait for primitive integer types used to represent the underlying type for field values
pub trait Int:
    Sized
    + Copy
    + Debug
    + Ord
    + Sub<Output = Self>
    + Into<u128>
    + From<u8>
    + Shr<u32, Output = Self>
    + BitAnd<Self, Output = Self>
    + PartialEq
{
    const BITS: u32;
}

impl Int for u8 {
    const BITS: u32 = u8::BITS;
}

impl Int for u32 {
    const BITS: u32 = u32::BITS;
}

pub trait Field:
    Add<Output = Self>
    + AddAssign
    + Neg<Output = Self>
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + From<u128>
    + Into<Self::Integer>
    + Clone
    + Copy
    + PartialEq
    + Debug
    + Send
    + Sized
    + 'static
{
    type Integer: Int;

    const PRIME: Self::Integer;
    const PRIME_TO_INTMAX_DELTA: Self::Integer;
    /// Additive identity element
    const ZERO: Self;
    /// Multiplicative identity element
    const ONE: Self;
    /// Derived from the size of the backing field, this constant indicates how much
    /// space is required to store this field value
    const SIZE_IN_BYTES: u32 = Self::Integer::BITS / 8;

    /// computes the multiplicative inverse of `self`. It is UB if `self` is 0.
    #[must_use]
    fn invert(&self) -> Self {
        debug_assert!(
            self != &Self::ZERO,
            "Multiplicative inverse is not defined for 0"
        );

        self.pow(Self::PRIME - Self::ONE.into() - Self::ONE.into())
    }

    /// Computes modular exponentiation, self^exp (mod PRIME)
    #[must_use]
    fn pow(&self, exp: Self::Integer) -> Self {
        let mut term = Self::ONE;
        // compute: x^exp
        // binary representation of exp: a_k*2^k + a_k-1*2^k-1 + ... + a_0*2^0
        // x^exp = x^a_0 + (x^2)^a_1 + ... + (x^(2^k))^a_k
        // * start at 0 and each time square the term.
        // * term contributes to the result iff a_k bit is 1 (as (x^a)^0 == 1)
        for i in (0..Self::Integer::BITS).rev() {
            term *= term;
            if (exp >> i) & Self::Integer::from(1) != Self::Integer::from(0) {
                term *= *self;
            }
        }

        term
    }

    /// Blanket implementation to represent the instance of this trait as 16 byte integer.
    /// Uses the fact that such conversion already exists via `Self` -> `Self::Integer` -> `Into<u128>`
    fn as_u128(&self) -> u128 {
        let int: Self::Integer = (*self).into();
        int.into()
    }

    /// Generic implementation to serialize fields into a buffer. Callers need to make sure
    /// there is enough capacity to store the value of this field.
    /// It is less efficient because it operates with generic representation of fields as 16 byte
    /// integers, so consider overriding it for actual field implementations
    ///
    /// ## Errors
    /// Returns an error if buffer did not have enough capacity to store this field value
    fn serialize(&self, buf: &mut [u8]) -> io::Result<()> {
        let raw_value = &self.as_u128().to_le_bytes()[..Self::SIZE_IN_BYTES as usize];

        if buf.len() >= raw_value.len() {
            buf[..Self::SIZE_IN_BYTES as usize].copy_from_slice(raw_value);
            Ok(())
        } else {
            let error_text = format!(
                "Buffer with total capacity {} cannot hold field value {:?} because \
                 it required at least {} bytes available",
                buf.len(),
                self,
                Self::SIZE_IN_BYTES
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
    fn deserialize(buf_from: &mut [u8]) -> io::Result<Self> {
        if Self::SIZE_IN_BYTES as usize <= buf_from.len() {
            let mut buf_to = [0; 16]; // one day...
            buf_to[..Self::SIZE_IN_BYTES as usize]
                .copy_from_slice(&buf_from[..Self::SIZE_IN_BYTES as usize]);

            Ok(Self::from(u128::from_le_bytes(buf_to)))
        } else {
            let error_text = format!(
                "Buffer is too small to read values of the field type {}. Required at least {} bytes,\
                 got {}", type_name::<Self>(), Self::SIZE_IN_BYTES, buf_from.len()
            );
            Err(io::Error::new(ErrorKind::UnexpectedEof, error_text))
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub trait BinaryField:
    Field
    + BitAnd<Output = Self>
    + BitAndAssign
    + BitOr<Output = Self>
    + BitOrAssign
    + BitXor<Output = Self>
    + BitXorAssign
    + Not
{
}
