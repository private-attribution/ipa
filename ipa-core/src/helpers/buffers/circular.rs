use std::ops::RangeInclusive;

use generic_array::GenericArray;
use typenum::Unsigned;

use crate::ff::Serializable;

/// This is a specialized version of circular buffer implementation,
/// tailored to what [`OrderingSender`] needs.
///
/// This construction requires one extra parameter, compared to
/// traditional ring buffers: `read_size` that specifies the smallest
/// continuous block of bytes that can be read off this buffer. It
/// also requires the total `capacity` and the size of one write
/// `write_size` to be provided at construction time. This allows it
/// to use a single allocation.
///
/// For example: if buffer capacity is set to 32k and `read_size` is
/// 4k, then buffer can only be read in blocks of 4k. `write_size` can
/// be any value, aligned with 4k `read_size`.
///
/// The capacity of this buffer does not need to be a power of two, although
/// you may want to have exactly that for performance of modulo operations
/// widely used internally.
///
/// This allows using this buffer in scenarios where the working window
/// is wide. If readers want smaller chunks of data, but can operate on
/// them fast enough, then writers experience less interruptions hitting
/// the capacity limit, because it can be set large enough.
///
/// This buffer can also be closed, using [`close`] method. After it is
/// closed, it allows reads of any size, but it guarantees that all of them
/// will be aligned with `write_size`.
///
/// ## Implementation notes
/// This buffer is built over a [`Vec`] with two extra pointers that indicate
/// the place to read from, and to write next chunk to. When read happens,
/// it moves the read pointer until it meets the write pointer.
/// When read points to the same location as write, this buffer is considered
/// empty.
///
/// Both pointers operate within the range `[0, 2*capacity)` and clamped into
/// the working range when used as index into the internal buffer. The reason
/// is to be able to distinguish empty and full buffers.
///
/// This implementation does not perform checks in optimized builds,
/// relying on [`OrderingSender`] to enforce correctness. If taken away,
/// necessary adjustments need to be made to avoid data corruption.
///
/// ## Alternative implementations
/// If alignment to `read_size` is too much, a [`BipBuffer`] can be used instead.
///
/// ## Future improvements
/// [`OrderingSender`] currently synchronizes reader and writers, but it does not
/// have to if this implementation is made thread-safe. There exists a well-known
/// lock-free FIFO implementation for a single producer, single consumer that uses
/// atomics for read and write pointers. We can't make use of it as is because there
/// are more than one writer. However, [`OrderingSender`] already knows how to allow
/// only one write at a time, so it could be possible to make the entire
/// implementation lock-free.
///
/// [`BipBuffer`]: <https://www.codeproject.com/Articles/3479/The-Bip-Buffer-The-Circular-Buffer-with-a-Twist>
/// [`OrderingSender`]: crate::helpers::buffers::OrderingSender
/// [`can_read`]: CircularBuf::can_read
/// [`close`]: CircularBuf::close
pub struct CircularBuf {
    /// write pointer, points to the beginning of the next write slice
    write: usize,
    /// read pointer, points to the beginning of the next read slice
    read: usize,
    /// The size of read returned from [`take`] if buffer is not closed and not empty.
    read_size: usize,
    /// The size of one write
    write_size: usize,
    /// Whether this buffer is closed
    closed: bool,
    /// Actual data, stored inside a contiguous region in memory.
    data: Vec<u8>,
}

impl CircularBuf {
    /// Constructs a new instance of [`CircularBuf`] with reserved `capacity` bytes and specified
    /// `write_size` and `read_size` bytes.
    ///
    /// ## Panics
    /// If any of the following conditions are met:
    /// * Any provided value is 0
    /// * `write_size` is not a multiple of `capacity`
    /// * `read_size` is not a multiple of `write_size`
    /// * `read_size` is smaller than `write_size`
    /// * `read_size` is larger than `capacity`
    pub fn new(capacity: usize, write_size: usize, read_size: usize) -> Self {
        debug_assert!(
            capacity > 0 && write_size > 0 && read_size > 0,
            "Capacity \"{capacity}\", write \"{write_size}\" and read size \"{read_size}\" must all be greater than zero"
        ); // enforced at the level above, so debug_assert is fine
        debug_assert!(
            capacity % write_size == 0,
            "\"{write_size}\" write size must divide capacity \"{capacity}\""
        );
        debug_assert!(
            read_size % write_size == 0,
            "\"{write_size}\" write size must divide read_size \"{read_size}\""
        );
        Self {
            write: 0,
            read: 0,
            write_size,
            read_size,
            closed: false,
            data: vec![0; capacity],
        }
    }

    /// Closes this buffer, making it read-only. After it is closed, it allows reads of any size,
    /// but it guarantees that all of them will be aligned with `write_size`.
    ///
    /// No writes will be accepted after buffer is closed.
    ///
    /// ## Panics
    /// if this buffer is already closed.
    pub fn close(&mut self) {
        debug_assert!(!self.closed, "Already closed");
        self.closed = true;
    }

    /// Returns a handle that allows to perform a single write to the buffer. Write must be exactly
    /// `write_size` bytes long and buffer must be open for writes and have sufficient capacity
    /// to fit it. [`can_write`] can be used to check all of these conditions.
    ///
    /// ## Panics
    /// If buffer is closed for writes or does not have enough capacity.
    ///
    /// [`can_write`]: Self::can_write
    pub fn next(&mut self) -> Next<'_> {
        debug_assert!(!self.closed, "Writing to a closed buffer");
        debug_assert!(
            self.can_write(),
            "Not enough space for the next write: only {av} bytes available, but at least {req} is required",
            av = self.remaining(),
            req = self.write_size
        );

        Next {
            range: self.range(self.write, self.write_size),
            buf: self,
        }
    }

    /// Performs a read off this buffer. if [`can_read`] is false before reading,
    /// this method will not panic, but will return an empty vector instead.
    ///
    /// if [`can_read`] is true before reading, this method is guaranteed to return
    /// a non-empty vector. The length of it depends on whether this buffer is
    /// closed or no. For closed buffers, the valid len will be in `[1, read_size]`
    /// range, but always aligned with `write_size`. For open buffers, len
    /// is always equal to `read_size`.
    ///
    /// [`can_read`]: Self::can_read
    pub fn take(&mut self) -> Vec<u8> {
        if !self.can_read() {
            return Vec::new();
        }

        // Capacity is always a multiple of write_size, so delta is always aligned.
        let delta = std::cmp::min(self.read_size, self.len());

        let mut ret = Vec::with_capacity(delta);
        let range = self.range(self.read, delta);

        // If the read range wraps around, we need to split it
        if range.end() < range.start() {
            ret.extend_from_slice(&self.data[*range.start()..]);
            ret.extend_from_slice(&self.data[..=*range.end()]);
        } else {
            ret.extend_from_slice(&self.data[range]);
        }

        self.read = self.inc(self.read, delta);

        ret
    }

    /// Returns the number of bytes in this buffer.
    pub fn len(&self) -> usize {
        // Modulo arithmetic and wrapping/overflow rules in Rust
        // make it difficult to write `(self.write - self.read) % 2*N`.
        // It works well for power-of-two sizes, but for arbitrary
        // buffer capacity, it is easier to use N - (a - b) because
        // write is always ahead of read.
        if self.write >= self.read {
            self.wrap(self.write - self.read)
        } else {
            self.capacity() + self.mask(self.write) - self.mask(self.read)
        }
    }

    /// Returns `true` if this buffer can be read from.
    pub fn can_read(&self) -> bool {
        (self.closed && !self.is_empty()) || self.len() >= self.read_size
    }

    /// Returns `true` if this buffer can be written into.
    pub fn can_write(&self) -> bool {
        !self.closed && self.remaining() >= self.write_size
    }

    /// Indicates whether this buffer is closed for writes.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Returns the capacity of this buffer, in bytes.
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    fn is_empty(&self) -> bool {
        self.read == self.write
    }

    fn remaining(&self) -> usize {
        self.capacity() - self.len()
    }

    fn mask(&self, val: usize) -> usize {
        val % self.data.len()
    }

    fn wrap(&self, val: usize) -> usize {
        val % (self.data.len() * 2)
    }

    fn inc(&self, val: usize, delta: usize) -> usize {
        self.wrap(val + delta)
    }

    /// Returns an inclusive range for the next `read` or `write` operation.
    /// Inclusive ranges make it easier to deal with wrap around % N. Specifically,
    /// when the write cursor points to the end of the buffer.
    fn range(&self, ptr: usize, unit: usize) -> RangeInclusive<usize> {
        self.mask(ptr)..=self.mask(ptr + unit - 1)
    }
}

/// A handle to write chunks of data directly inside [`CircularBuf`] using [`CircularBuf::next`]
/// method.
pub struct Next<'a> {
    range: RangeInclusive<usize>,
    buf: &'a mut CircularBuf,
}

impl Next<'_> {
    /// Writes `M` into a slice reserved inside the [`CircularBuf`].
    ///
    /// ## Panics
    /// If the size of `M` is not equal to `write_size` of [`CircularBuf`]
    pub fn write<B: BufWriteable + ?Sized>(self, data: &B) {
        assert_eq!(
            data.size(),
            self.buf.write_size,
            "Expect to keep messages of size {}, got {}",
            self.buf.write_size,
            data.size()
        );
        data.write(&mut self.buf.data[self.range]);

        self.buf.write = self.buf.inc(self.buf.write, self.buf.write_size);
    }
}

/// A trait that allows to write data into a [`CircularBuf`] using [`Next`] handle.
/// It all exists to bring [`Serializable`] and slice interfaces together.
pub trait BufWriteable {
    /// Returns the size of the writeable.
    fn size(&self) -> usize;

    /// Writes self into `data`. This method does not need to do bounds check, it is performed
    /// by the caller of it.
    fn write(&self, data: &mut [u8]);
}

impl<M: Serializable> BufWriteable for M {
    fn size(&self) -> usize {
        M::Size::USIZE
    }

    fn write(&self, data: &mut [u8]) {
        let slice = GenericArray::from_mut_slice(data);
        self.serialize(slice);
    }
}

impl BufWriteable for [u8] {
    fn size(&self) -> usize {
        self.len()
    }

    fn write(&self, data: &mut [u8]) {
        data.copy_from_slice(self);
    }
}

#[cfg(all(test, unit_test))]
#[allow(clippy::cast_possible_truncation)]
mod test {
    #[cfg(debug_assertions)]
    use std::panic;
    use std::{
        convert::Infallible,
        fmt::{Debug, Formatter},
        marker::PhantomData,
    };

    use generic_array::GenericArray;
    use serde::Serializer;
    use typenum::{U1, U2, Unsigned};

    use super::CircularBuf;
    use crate::ff::Serializable;

    fn new_buf<B: BufSetup>() -> CircularBuf {
        let capacity = B::CAPACITY * B::UNIT_SIZE;
        let write_size = B::UNIT_SIZE;
        let read_size = B::READ_SIZE * B::UNIT_SIZE;

        CircularBuf::new(capacity, write_size, read_size)
    }

    #[cfg(debug_assertions)]
    fn unwind_panic_to_str<F: FnOnce() -> CircularBuf>(f: F) -> String {
        let err = panic::catch_unwind(panic::AssertUnwindSafe(f))
            .err()
            .unwrap();
        let err = err.downcast::<String>().unwrap();

        err.to_string()
    }

    trait BufItem: Serializable + for<'a> From<&'a usize> {}
    impl<V: Serializable + for<'a> From<&'a usize>> BufItem for V {}

    trait BufSetup {
        type Item: BufItem;

        /// The size of one element in the buffer, in bytes.
        const UNIT_SIZE: usize = <Self::Item as Serializable>::Size::USIZE;
        /// Capacity of the buffer, in units of [`UNIT_SIZE`].
        const CAPACITY: usize;
        /// Number of units written before buffer opens for reads, in units of [`UNIT_SIZE`].
        const READ_SIZE: usize;

        fn fill(buf: &mut CircularBuf) {
            for i in 0..Self::CAPACITY {
                buf.next().write(&Self::Item::from(&i));
            }
        }

        fn read_once(buf: &mut CircularBuf) -> Vec<usize>
        where
            usize: From<Self::Item>,
        {
            buf.take()
                .chunks(Self::UNIT_SIZE)
                .map(|chunk| Self::Item::deserialize(GenericArray::from_slice(chunk)).unwrap())
                .map(usize::from)
                .collect()
        }
    }

    #[derive(Ord, PartialOrd, Eq, PartialEq)]
    struct TwoBytes([u8; 2]);

    impl Serializable for TwoBytes {
        type Size = U2;
        type DeserializationError = Infallible;

        fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
            buf[0] = self.0[0];
            buf[1] = self.0[1];
        }

        fn deserialize(
            buf: &GenericArray<u8, Self::Size>,
        ) -> Result<Self, Self::DeserializationError> {
            Ok(Self([buf[0], buf[1]]))
        }
    }

    struct FiveElements<B: BufItem = TwoBytes>(PhantomData<B>);
    impl<B: BufItem> BufSetup for FiveElements<B> {
        type Item = B;

        const UNIT_SIZE: usize = 2;
        const CAPACITY: usize = 5;
        const READ_SIZE: usize = 2;
    }

    struct One<B: BufItem = TwoBytes>(PhantomData<B>);
    impl<B: BufItem> BufSetup for One<B> {
        type Item = B;
        const CAPACITY: usize = 1;
        const READ_SIZE: usize = 1;
    }

    impl From<&usize> for TwoBytes {
        fn from(v: &usize) -> Self {
            let v = *v;
            assert!(u16::try_from(v).is_ok());
            Self([v as u8, (v >> 8) as u8])
        }
    }

    impl From<TwoBytes> for usize {
        fn from(value: TwoBytes) -> Self {
            usize::from(u16::from_le_bytes(value.0))
        }
    }

    impl Debug for TwoBytes {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.serialize_u16(u16::from_le_bytes(self.0))
        }
    }

    #[test]
    fn empty() {
        type CircularBuf = FiveElements<TwoBytes>;

        let buf = new_buf::<CircularBuf>();
        assert_eq!(0, buf.len());
        assert_eq!(
            CircularBuf::CAPACITY * CircularBuf::UNIT_SIZE,
            buf.capacity()
        );
        assert!(buf.can_write());
        assert!(!buf.can_read());
    }

    #[test]
    fn seq_write_read() {
        type CircularBuf = FiveElements<TwoBytes>;

        assert_ne!(
            0,
            CircularBuf::CAPACITY % CircularBuf::READ_SIZE,
            "This test requires buffers to be partially filled"
        );
        assert_ne!(
            1,
            CircularBuf::CAPACITY / CircularBuf::READ_SIZE,
            "This test requires buffers to be partially filled"
        );

        let mut buf = new_buf::<CircularBuf>();
        let input = (0..=CircularBuf::CAPACITY).collect::<Vec<_>>();
        let mut output = Vec::with_capacity(CircularBuf::CAPACITY);

        let mut iter = input.iter();
        while buf.can_write() {
            buf.next().write(&TwoBytes::from(iter.next().unwrap()));
        }

        assert!(!buf.can_write());
        assert!(buf.can_read());

        while buf.can_read() {
            output.extend(CircularBuf::read_once(&mut buf));
        }

        assert!(buf.can_write());
        assert!(!buf.is_empty());
        assert!(!buf.can_read());

        while (buf.len() / CircularBuf::UNIT_SIZE) < CircularBuf::READ_SIZE {
            buf.next().write(&TwoBytes::from(iter.next().unwrap()));
        }

        assert!(buf.can_write());
        output.extend(CircularBuf::read_once(&mut buf));

        assert!(buf.is_empty());
        assert_eq!(input, output);
    }

    #[test]
    fn wrap_around() {
        type CircularBuf = FiveElements<TwoBytes>;

        let mut buf = new_buf::<CircularBuf>();
        CircularBuf::fill(&mut buf);
        let _ = buf.take();

        // should be able to write more now
        while (buf.len() / CircularBuf::UNIT_SIZE) % CircularBuf::READ_SIZE != 0 {
            buf.next().write(&TwoBytes::from(&0));
        }

        while buf.can_read() {
            let _ = buf.take();
        }

        assert!(buf.is_empty());
    }

    #[test]
    fn read_size_wrap() {
        struct Six;
        impl BufSetup for Six {
            type Item = TwoBytes;
            const CAPACITY: usize = 6;
            const READ_SIZE: usize = 4;
        }

        let mut buf = new_buf::<Six>();
        Six::fill(&mut buf);

        let mut output = Vec::new();
        output.extend(Six::read_once(&mut buf));
        buf.next().write(&TwoBytes::from(&6));
        buf.next().write(&TwoBytes::from(&7));
        assert!(!buf.is_closed());
        buf.close();
        assert!(buf.is_closed());

        output.extend(Six::read_once(&mut buf));

        assert_eq!((0..8).collect::<Vec<_>>(), output);
    }

    #[test]
    fn write_more_than_twice_capacity() {
        fn fill_take(buf: &mut CircularBuf) {
            One::<TwoBytes>::fill(buf);
            assert_eq!(2, buf.len());
            let _ = buf.take();
            assert_eq!(0, buf.len());
        }

        let mut buf = new_buf::<One<TwoBytes>>();
        fill_take(&mut buf);
        fill_take(&mut buf);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn panic_on_zero() {
        fn check_panic(capacity: usize, write_size: usize, read_size: usize) {
            let err = format!(
                "Capacity \"{capacity}\", write \"{write_size}\" and read size \"{read_size}\" must all be greater than zero"
            );

            assert_eq!(
                err,
                unwind_panic_to_str(|| CircularBuf::new(capacity, write_size, read_size))
            );
        }

        check_panic(0, 0, 0);
        check_panic(2, 0, 0);
        check_panic(2, 2, 0);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn panic_on_bad_write_size() {
        let capacity = 3;
        let write_size = 2;
        let err = format!("\"{write_size}\" write size must divide capacity \"{capacity}\"");

        assert_eq!(
            err,
            unwind_panic_to_str(|| CircularBuf::new(capacity, write_size, 2))
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn panic_on_bad_read_size() {
        let capacity = 6;
        let write_size = 2;
        let read_size = 3;

        assert_eq!(
            format!("\"{write_size}\" write size must divide read_size \"{read_size}\""),
            unwind_panic_to_str(|| CircularBuf::new(capacity, write_size, read_size))
        );
        assert_eq!(
            format!("\"{read_size}\" write size must divide read_size \"{write_size}\""),
            unwind_panic_to_str(|| CircularBuf::new(capacity, read_size, write_size))
        );
    }

    #[test]
    fn take() {
        type CircularBuf = FiveElements<TwoBytes>;
        // take is greedy and when called is going to get whatever is available
        let mut buf = new_buf::<CircularBuf>();
        CircularBuf::fill(&mut buf);
        // can take the whole read_size chunk
        assert_eq!(vec![0, 1], CircularBuf::read_once(&mut buf));
        assert_eq!(vec![2, 3], CircularBuf::read_once(&mut buf));

        // the last item is available only after buffer is closed
        assert_eq!(Vec::<usize>::new(), CircularBuf::read_once(&mut buf));

        buf.close();
        assert!(!buf.can_write());
        assert_eq!(vec![4], CircularBuf::read_once(&mut buf));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Already closed")]
    fn close_twice() {
        let mut buf = new_buf::<FiveElements>();
        buf.close();
        buf.close();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Writing to a closed buffer")]
    fn no_writes_after_close() {
        let mut buf = new_buf::<FiveElements>();
        buf.close();
        buf.next().write(&TwoBytes::from(&0));
    }

    #[test]
    #[should_panic(expected = "Expect to keep messages of size 2, got 1")]
    fn bad_write() {
        let mut buf = new_buf::<FiveElements<TwoBytes>>();
        buf.next().write([0_u8].as_slice());
    }

    fn test_one<T: BufSetup>()
    where
        usize: From<T::Item>,
    {
        let mut buf = new_buf::<T>();
        T::fill(&mut buf);
        assert!(!buf.can_write());
        assert!(buf.can_read());
        assert_eq!(vec![0], T::read_once(&mut buf));
        assert!(buf.is_empty());
    }

    #[test]
    fn single_element_two_bytes() {
        test_one::<One<TwoBytes>>();
    }

    #[test]
    fn single_element_one_byte() {
        struct OneByte(u8);
        impl Serializable for OneByte {
            type Size = U1;
            type DeserializationError = Infallible;

            fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
                buf[0] = self.0;
            }

            fn deserialize(
                buf: &GenericArray<u8, Self::Size>,
            ) -> Result<Self, Self::DeserializationError> {
                Ok(Self(buf[0]))
            }
        }
        impl From<&usize> for OneByte {
            fn from(value: &usize) -> Self {
                Self(u8::try_from(*value).unwrap())
            }
        }

        impl From<OneByte> for usize {
            fn from(value: OneByte) -> Self {
                Self::from(value.0)
            }
        }

        test_one::<One<OneByte>>();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(
        expected = "Not enough space for the next write: only 0 bytes available, but at least 2 is required"
    )]
    fn not_enough_space() {
        type CircularBuf = FiveElements<TwoBytes>;

        let mut buf = new_buf::<CircularBuf>();
        CircularBuf::fill(&mut buf);

        let _ = buf.next();
    }

    mod prop_tests {
        use std::num::Wrapping;

        use proptest::{arbitrary::any, prop_compose, proptest, strategy::Just};
        use rand::{
            Rng,
            distributions::{Distribution, Standard},
            rngs::StdRng,
        };
        use rand_core::SeedableRng;

        use crate::helpers::buffers::circular::CircularBuf;

        #[derive(Debug)]
        struct BufSetup {
            write_size: usize,
            read_size: usize,
            capacity: usize,
        }

        prop_compose! {
            fn arb_buf(max_write_size: usize, max_units: usize)
                      (write_size in 1..max_write_size, read_units in 1..max_units)
                      (write_size in Just(write_size), read_units in Just(read_units), capacity_units in read_units..max_units)
            -> BufSetup {
                BufSetup {
                    write_size,
                    read_size: read_units * write_size,
                    capacity: capacity_units * write_size
                }
            }
        }

        impl From<BufSetup> for CircularBuf {
            fn from(value: BufSetup) -> Self {
                CircularBuf::new(value.capacity, value.write_size, value.read_size)
            }
        }

        #[derive(Debug, Eq, PartialEq)]
        enum Decision {
            Read,
            Write,
        }

        impl Distribution<Decision> for Standard {
            fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Decision {
                if rng.r#gen() {
                    Decision::Read
                } else {
                    Decision::Write
                }
            }
        }

        fn pack(val: u8, dest_bytes: usize) -> Vec<u8> {
            let mut data = vec![0; dest_bytes];
            data[0] = val;

            data
        }

        fn take_next(buf: &mut CircularBuf, unit_size: usize) -> Vec<u8> {
            buf.take()
                .as_slice()
                .chunks(unit_size)
                .map(|chunk| chunk[0])
                .collect()
        }

        fn read_write(setup: BufSetup, ops: u32, seed: u64) {
            let mut buf = CircularBuf::from(setup);
            let mut cnt = Wrapping::<u8>::default();
            let mut written = Vec::new();
            let mut read = Vec::new();
            let mut rng = StdRng::seed_from_u64(seed);
            let write_size = buf.write_size;

            for _ in 0..ops {
                if rng.r#gen::<Decision>() == Decision::Write && buf.can_write() {
                    buf.next().write(pack(cnt.0, write_size).as_slice());
                    written.push(cnt.0);
                    cnt += 1;
                } else if buf.can_read() {
                    read.extend(take_next(&mut buf, write_size));
                }
            }
            buf.close();

            while !buf.is_empty() {
                read.extend(take_next(&mut buf, write_size));
            }

            assert_eq!(written, read);
        }

        proptest! {
            #[test]
            fn arb_read_write(setup in arb_buf(25, 99), ops in 1..1000u32, seed in any::<u64>()) {
                read_write(setup, ops, seed);
            }
        }
    }
}
