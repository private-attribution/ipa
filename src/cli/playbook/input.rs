use crate::ff::Field;

use std::fs::File;
use std::io;
use std::io::{stdin, BufRead, BufReader, Read};

use crate::{bits::BitArray, ipa_test_input, test_fixture::input::GenericReportTestInput};
use std::path::PathBuf;

pub trait InputItem {
    fn from_str(s: &str) -> Self;
}

impl<F: Field> InputItem for F {
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

impl<F: Field, MK: BitArray, BK: BitArray> InputItem for GenericReportTestInput<F, MK, BK> {
    fn from_str(s: &str) -> Self {
        if let [match_key, is_trigger_bit, breakdown_key, trigger_value] =
            s.splitn(4, ',').collect::<Vec<_>>()[..]
        {
            let records: Vec<GenericReportTestInput<F, MK, BK>> = ipa_test_input!(
                [
                    {
                        match_key: match_key.parse::<u128>().unwrap(),
                        is_trigger_report: is_trigger_bit.parse::<u128>().unwrap(),
                        breakdown_key: breakdown_key.parse::<u128>().unwrap(),
                        trigger_value: trigger_value.parse::<u128>().unwrap()
                    },
                ];
                (F, MK, BK)
            );
            records[0]
        } else {
            panic!("{s} is not a valid IPAInputTestRow")
        }
    }
}

impl<I: InputItem> InputItem for (I, I) {
    fn from_str(s: &str) -> Self {
        if let Some((left, right)) = s.split_once(',') {
            (I::from_str(left), I::from_str(right))
        } else {
            panic!("{s} is not a valid tuple of input elements");
        }
    }
}

pub struct InputSource {
    inner: Box<dyn BufRead>,
}

impl InputSource {
    /// Opens a new input source from the given file.
    ///
    /// ## Panics
    /// This function will panic  if `path` does not already exist.
    #[must_use]
    pub fn from_file(path: &PathBuf) -> Self {
        Self {
            inner: Box::new(BufReader::new(File::open(path).unwrap())),
        }
    }

    #[must_use]
    pub fn from_stdin() -> Self {
        Self {
            inner: Box::new(BufReader::new(stdin())),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn from_static_str(input: &'static str) -> Self {
        Self {
            inner: Box::new(BufReader::new(input.as_bytes())),
        }
    }

    pub fn iter<T: InputItem>(self) -> impl Iterator<Item = T> {
        self.lines()
            .filter_map(|line| line.map(|l| T::from_str(&l)).ok())
    }
}

impl Read for InputSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl BufRead for InputSource {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt);
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
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
        assert_eq!(
            (Fp31::from(20_u128), Fp31::from(27_u128)),
            shares.reconstruct()
        );
    }

    #[test]
    #[should_panic]
    fn tuple_parse_error() {
        <(Fp31, Fp31)>::from_str("20,");
    }

    mod input_source {
        use super::*;
        use crate::cli::playbook::input::InputSource;
        use crate::ff::Field;

        #[test]
        fn multiline() {
            let expected = vec![(1_u128, 2_u128), (3, 4)];

            let source = InputSource::from_static_str("1,2\n3,4");
            let actual = source
                .iter::<(Fp31, Fp31)>()
                .map(|(l, r)| (l.as_u128(), r.as_u128()))
                .collect::<Vec<_>>();

            assert_eq!(expected, actual);
        }
    }
}
