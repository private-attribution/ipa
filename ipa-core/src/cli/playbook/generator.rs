use std::io::{Cursor, Read, Write};

/// This generator generates random u128 values
/// and implements [`Read`] trait to return those values.
///
/// This allows numbers to be generated in a streaming
/// fashion, making it possible to generate large amounts
pub(super) struct U128Generator {
    pos: usize,
    max: usize,
}

impl U128Generator {
    pub fn new(count: u64) -> Self {
        Self {
            pos: 0,
            max: usize::try_from(count).unwrap(),
        }
    }
}

impl Read for U128Generator {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let sz = u64::try_from(buf.len()).unwrap();
        let mut cur = Cursor::new(buf);
        while cur.position() < sz && self.pos < self.max {
            let l: u128 = rand::random();
            assert_eq!(16, cur.write(&l.to_le_bytes())?);
            self.pos += 1;
        }

        Ok(usize::try_from(cur.position()).unwrap())
    }
}
