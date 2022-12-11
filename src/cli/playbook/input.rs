use std::any::type_name;
use std::num::ParseIntError;
use std::str::FromStr;
use crate::ff::{Field, Fp31, Fp32BitPrime};
use crate::secret_sharing::IntoShares;

trait InputItem : Sized {
    fn from_str(s: &str) -> Self;
}

impl <F: Field> InputItem for F {
    fn from_str(s: &str) -> Self {
        let int_v = s.parse::<u128>().unwrap();
        F::from(int_v)
    }
}

impl InputItem for u64 {
    fn from_str(s: &str) -> Self {
        s.parse::<u64>().unwrap()
    }
}

impl <I: InputItem> InputItem for (I, I) {
    fn from_str(s: &str) -> Self {
        let mut iter= s.split(',');
        match (iter.next(), iter.next()) {
            (Some(left), Some(right)) => (I::from_str(left), I::from_str(right)),
            _ => panic!("{s} is not a valid tuple of input elements: {}", type_name::<I>())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cli::playbook::input::InputItem;
    use crate::ff::{Fp31, Fp32BitPrime};
    use crate::secret_sharing::IntoShares;
    use crate::test_fixture::Reconstruct;

    #[test]
    fn from_str() {
        assert_eq!(Fp31::from(1_u128), Fp31::from_str("1"));
        assert_eq!(Fp32BitPrime::from(0_u128), Fp32BitPrime::from_str("0"));
        assert_eq!(6_u64, u64::from_str("6"));
    }

    #[test]
    #[should_panic]
    fn parse_negative() {
        Fp31::from_str("-1");
    }

    #[test]
    #[should_panic]
    fn parse_empty() {
        Fp31::from_str("");
    }

    #[test]
    fn tuple() {
        let input = "20,27";
        let tp = <(Fp31, Fp31)>::from_str(input);
        let shares = tp.share();
        assert_eq!((Fp31::from(20_u128), Fp31::from(27_u128)), shares.reconstruct());
    }

    #[test]
    #[should_panic]
    fn tuple_parse_error() {
        <(Fp31, Fp31)>::from_str("20,");
    }
}
