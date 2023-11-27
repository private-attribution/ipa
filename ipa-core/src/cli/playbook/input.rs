use std::{
    any::type_name,
    fs::File,
    io,
    io::{stdin, BufRead, BufReader, Read},
    path::PathBuf,
};

use crate::{
    ff::{Field, GaloisField},
    ipa_test_input,
    test_fixture::{input::GenericReportTestInput, ipa::TestRawDataRecord},
};

pub trait InputItem {
    fn from_str(s: &str) -> Self;
}

impl<F: Field> InputItem for F {
    fn from_str(s: &str) -> Self {
        let int_v = s.parse::<u128>().unwrap();
        F::truncate_from(int_v)
    }
}

impl InputItem for u64 {
    fn from_str(s: &str) -> Self {
        s.parse::<u64>().unwrap()
    }
}

impl<F: Field, MK: GaloisField, BK: GaloisField> InputItem for GenericReportTestInput<F, MK, BK> {
    fn from_str(s: &str) -> Self {
        if let [ts, match_key, is_trigger_bit, breakdown_key, trigger_value] =
            s.splitn(5, ',').collect::<Vec<_>>()[..]
        {
            ipa_test_input!({
                    timestamp: ts.parse::<u128>().unwrap(),
                    match_key: match_key.parse::<u128>().unwrap(),
                    is_trigger_report: is_trigger_bit.parse::<u128>().unwrap(),
                    breakdown_key: breakdown_key.parse::<u128>().unwrap(),
                    trigger_value: trigger_value.parse::<u128>().unwrap()
                };
                (F, MK, BK)
            )
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

impl InputItem for TestRawDataRecord {
    fn from_str(s: &str) -> Self {
        if let [ts, match_key, is_trigger_bit, breakdown_key, trigger_value] =
            s.splitn(5, ',').collect::<Vec<_>>()[..]
        {
            TestRawDataRecord {
                user_id: match_key.parse().unwrap(),
                timestamp: ts.parse().unwrap(),
                is_trigger_report: is_trigger_bit.parse::<u8>().unwrap() == 1,
                breakdown_key: breakdown_key.parse().unwrap(),
                trigger_value: trigger_value.parse().unwrap(),
            }
        } else {
            panic!("{s} is not a valid {}", type_name::<Self>())
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

    pub fn to_vec(mut self) -> Result<Vec<u8>, io::Error> {
        let mut buf = vec![];
        self.read_to_end(&mut buf)?;

        Ok(buf)
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

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        cli::playbook::input::InputItem,
        ff::{Fp31, Fp32BitPrime},
        secret_sharing::IntoShares,
        test_fixture::Reconstruct,
    };

    #[test]
    fn from_str() {
        assert_eq!(Fp31::try_from(1_u128).unwrap(), Fp31::from_str("1"));
        assert_eq!(
            Fp32BitPrime::try_from(0_u128).unwrap(),
            Fp32BitPrime::from_str("0")
        );
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
            (
                Fp31::try_from(20_u128).unwrap(),
                Fp31::try_from(27_u128).unwrap()
            ),
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
        use crate::{cli::playbook::input::InputSource, ff::Field};

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
