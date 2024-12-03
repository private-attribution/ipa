use std::{
    any::type_name,
    fs::File,
    io,
    io::{stdin, BufRead, BufReader, Read},
    path::PathBuf,
};

use crate::{
    cli::playbook::generator::U128Generator,
    ff::U128Conversions,
    test_fixture::{hybrid::TestHybridRecord, ipa::TestRawDataRecord},
};

pub trait InputItem {
    fn from_str(s: &str) -> Self;
}

impl<T: U128Conversions> InputItem for T {
    fn from_str(s: &str) -> Self {
        let int_v = s.parse::<u128>().unwrap();
        T::truncate_from(int_v)
    }
}

impl InputItem for u64 {
    fn from_str(s: &str) -> Self {
        s.parse::<u64>().unwrap()
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

impl InputItem for TestHybridRecord {
    fn from_str(s: &str) -> Self {
        let event_type = s.chars().nth(0).unwrap();
        match event_type {
            'i' => {
                if let [_, match_key, number, key_id, helper_origin] =
                    s.splitn(5, ',').collect::<Vec<_>>()[..]
                {
                    let match_key: u64 = match_key
                        .parse()
                        .unwrap_or_else(|e| panic!("Expected a u64, got {match_key}: {e}"));

                    let number: u32 = number
                        .parse()
                        .unwrap_or_else(|e| panic!("Expected a u32, got {number}: {e}"));

                    let key_id: u8 = key_id
                        .parse()
                        .unwrap_or_else(|e| panic!("Expected a u8, got {key_id}: {e}"));
                    TestHybridRecord::TestImpression {
                        match_key,
                        breakdown_key: number,
                        key_id,
                        helper_origin: helper_origin.to_string(),
                    }
                } else {
                    panic!("{s} is not a valid {}", type_name::<Self>())
                }
            }

            'c' => {
                if let [_, match_key, number, key_id, helper_origin, conversion_site_domain, timestamp, epsilon, sensitivity] =
                    s.splitn(9, ',').collect::<Vec<_>>()[..]
                {
                    let match_key: u64 = match_key
                        .parse()
                        .unwrap_or_else(|e| panic!("Expected a u64, got {match_key}: {e}"));

                    let number: u32 = number
                        .parse()
                        .unwrap_or_else(|e| panic!("Expected a u32, got {number}: {e}"));

                    let key_id: u8 = key_id
                        .parse()
                        .unwrap_or_else(|e| panic!("Expected a u8, got {key_id}: {e}"));

                    let timestamp: u64 = timestamp
                        .parse()
                        .unwrap_or_else(|e| panic!("Expected a u64, got {timestamp}: {e}"));

                    let epsilon: f64 = epsilon
                        .parse()
                        .unwrap_or_else(|e| panic!("Expected an f64, got {epsilon}: {e}"));

                    let sensitivity: f64 = sensitivity
                        .parse()
                        .unwrap_or_else(|e| panic!("Expected an f64, got {sensitivity}: {e}"));
                    TestHybridRecord::TestConversion {
                        match_key,
                        value: number,
                        key_id,
                        helper_origin: helper_origin.to_string(),
                        conversion_site_domain: conversion_site_domain.to_string(),
                        timestamp,
                        epsilon,
                        sensitivity,
                    }
                } else {
                    panic!("{s} is not a valid {}", type_name::<Self>())
                }
            }
            _ => panic!(
                "{}",
                format!(
                    "Invalid input. Rows should start with 'i' or 'c'. Did not expect {event_type}"
                )
            ),
        }
    }
}

pub struct InputSource {
    inner: Box<dyn BufRead>,
    sz: Option<u64>,
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
            sz: None,
        }
    }

    #[must_use]
    pub fn from_stdin() -> Self {
        Self {
            inner: Box::new(BufReader::new(stdin())),
            sz: None,
        }
    }

    #[must_use]
    pub fn from_generator(count: u64) -> Self {
        Self {
            inner: Box::new(BufReader::new(U128Generator::new(count))),
            sz: Some(count),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn from_static_str(input: &'static str) -> Self {
        Self {
            inner: Box::new(BufReader::new(input.as_bytes())),
            sz: None,
        }
    }

    pub fn iter<T: InputItem>(self) -> impl Iterator<Item = T> {
        self.lines()
            .filter_map(|line| line.map(|l| T::from_str(&l)).ok())
    }

    /// This method returns an iterator with known size that yields
    /// [`u128`] values that can be later converted to any field.
    /// # Panics
    /// This will panic if input was created from a file or any other
    /// source where the size of it is not known in advance.
    /// Currently only [`Self::from_generator`] allows for this method
    /// to work.
    #[must_use]
    pub fn known_size_iter(self) -> impl ExactSizeIterator<Item = u128> {
        if let Some(sz) = &self.sz {
            U128Reader {
                inner: self.inner,
                count: usize::try_from(*sz).unwrap(),
            }
        } else {
            panic!("Can't build an iterator with known size from this input type.")
        }
    }

    /// Reads all the bytes from this instance and returns an owned buffer that contains them.
    ///
    /// ## Errors
    /// if the underlying IO resource returns an error while reading from it.
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

/// A bridge between [`BufRead`] and [`Iterator`]
/// that only works for 16 byte values read from
/// the buffer. It never reads more than `count`
/// elements from the buffer.
struct U128Reader {
    inner: Box<dyn BufRead>,
    count: usize,
}

impl Iterator for U128Reader {
    type Item = u128;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }

        let mut buf = [0_u8; 16];
        self.inner
            .read_exact(&mut buf)
            .expect("Buffer does not have enough bytes to read the next u128 element");
        self.count -= 1;
        Some(u128::from_le_bytes(buf))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.count, Some(self.count))
    }
}

impl ExactSizeIterator for U128Reader {}

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
    #[should_panic(expected = "ParseIntError")]
    fn parse_negative() {
        Fp31::from_str("-1");
    }

    #[test]
    #[should_panic(expected = "ParseIntError")]
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
    #[should_panic(expected = "ParseIntError")]
    fn tuple_parse_error() {
        <(Fp31, Fp31)>::from_str("20,");
    }

    mod input_source {
        use super::*;
        use crate::{cli::playbook::input::InputSource, ff::U128Conversions};

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
