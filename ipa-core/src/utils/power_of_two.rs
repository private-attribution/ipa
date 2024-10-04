use std::{fmt::Display, num::NonZeroUsize, str::FromStr};

#[derive(Debug, thiserror::Error)]
#[error("{0} is not a power of two or not within the 1..u32::MAX range")]
pub struct ConvertError<I: Display>(I);

impl<I: PartialEq + Display> PartialEq for ConvertError<I> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// This construction guarantees the value to be a power of two and
/// within the range 0..2^32-1
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct NonZeroU32PowerOfTwo(u32);

impl Display for NonZeroU32PowerOfTwo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u32::from(*self))
    }
}

impl TryFrom<usize> for NonZeroU32PowerOfTwo {
    type Error = ConvertError<usize>;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > 0 && value < usize::try_from(u32::MAX).unwrap() && value.is_power_of_two() {
            Ok(NonZeroU32PowerOfTwo(u32::try_from(value).unwrap()))
        } else {
            Err(ConvertError(value))
        }
    }
}

impl From<NonZeroU32PowerOfTwo> for usize {
    fn from(value: NonZeroU32PowerOfTwo) -> Self {
        // we are using 64 bit registers
        usize::try_from(value.0).unwrap()
    }
}

impl From<NonZeroU32PowerOfTwo> for u32 {
    fn from(value: NonZeroU32PowerOfTwo) -> Self {
        value.0
    }
}

impl FromStr for NonZeroU32PowerOfTwo {
    type Err = ConvertError<String>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = s.parse::<usize>().map_err(|_| ConvertError(s.to_owned()))?;
        NonZeroU32PowerOfTwo::try_from(v).map_err(|_| ConvertError(s.to_owned()))
    }
}

impl NonZeroU32PowerOfTwo {
    #[must_use]
    pub fn to_non_zero_usize(self) -> NonZeroUsize {
        let v = usize::from(self);
        NonZeroUsize::new(v).unwrap_or_else(|| unreachable!())
    }

    #[must_use]
    pub fn get(self) -> usize {
        usize::from(self)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::{ConvertError, NonZeroU32PowerOfTwo};

    #[test]
    fn rejects_invalid_values() {
        assert!(matches!(
            NonZeroU32PowerOfTwo::try_from(0),
            Err(ConvertError(0))
        ));
        assert!(matches!(
            NonZeroU32PowerOfTwo::try_from(3),
            Err(ConvertError(3))
        ));

        assert!(matches!(
            NonZeroU32PowerOfTwo::try_from(1_usize << 33),
            Err(ConvertError(_))
        ));
    }

    #[test]
    fn accepts_valid() {
        assert_eq!(4, u32::from(NonZeroU32PowerOfTwo::try_from(4).unwrap()));
        assert_eq!(16, u32::from(NonZeroU32PowerOfTwo::try_from(16).unwrap()));
    }

    #[test]
    fn parse_from_str() {
        assert_eq!(NonZeroU32PowerOfTwo(4), "4".parse().unwrap());
        assert_eq!(
            ConvertError("0".to_owned()),
            "0".parse::<NonZeroU32PowerOfTwo>().unwrap_err()
        );
        assert_eq!(
            ConvertError("3".to_owned()),
            "3".parse::<NonZeroU32PowerOfTwo>().unwrap_err()
        );
    }
}
