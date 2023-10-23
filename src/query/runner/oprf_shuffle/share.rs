use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use generic_array::GenericArray;
use rand::{distributions::Standard, Rng};
use typenum::Unsigned;

use super::ShuffleInputRow;
use crate::{
    ff::{Field, Gf32Bit, Gf40Bit, Gf8Bit, Serializable},
    helpers::Direction,
    secret_sharing::SharedValue,
};
pub type ShuffleShareMK = Gf40Bit;
pub type ShuffleShareBK = Gf8Bit;
pub type ShuffleShareF = Gf32Bit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShuffleShare {
    pub timestamp: ShuffleShareF,
    pub mk: ShuffleShareMK,
    pub is_trigger_bit: ShuffleShareF,
    pub breakdown_key: ShuffleShareBK,
    pub trigger_value: ShuffleShareF,
}

impl AddAssign for ShuffleShare {
    fn add_assign(&mut self, rhs: Self) {
        self.timestamp += rhs.timestamp;
        self.mk += rhs.mk;
        self.is_trigger_bit += rhs.is_trigger_bit;
        self.breakdown_key += rhs.breakdown_key;
        self.trigger_value += rhs.trigger_value;
    }
}
impl Sub for ShuffleShare {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output {
            timestamp: self.timestamp - rhs.timestamp,
            mk: self.mk - rhs.mk,
            is_trigger_bit: self.is_trigger_bit - rhs.is_trigger_bit,
            breakdown_key: self.breakdown_key - rhs.breakdown_key,
            trigger_value: self.trigger_value - rhs.trigger_value,
        }
    }
}
impl SubAssign for ShuffleShare {
    fn sub_assign(&mut self, rhs: Self) {
        self.timestamp -= rhs.timestamp;
        self.mk -= rhs.mk;
        self.is_trigger_bit -= rhs.is_trigger_bit;
        self.breakdown_key -= rhs.breakdown_key;
        self.trigger_value -= rhs.trigger_value;
    }
}
impl Neg for ShuffleShare {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::Output {
            timestamp: self.timestamp.neg(),
            mk: self.mk.neg(),
            is_trigger_bit: self.is_trigger_bit.neg(),
            breakdown_key: self.breakdown_key.neg(),
            trigger_value: self.trigger_value.neg(),
        }
    }
}
impl Mul for ShuffleShare {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::Output {
            timestamp: self.timestamp * rhs.timestamp,
            mk: self.mk * rhs.mk,
            is_trigger_bit: self.is_trigger_bit * rhs.is_trigger_bit,
            breakdown_key: self.breakdown_key * rhs.breakdown_key,
            trigger_value: self.trigger_value * rhs.trigger_value,
        }
    }
}
impl MulAssign for ShuffleShare {
    fn mul_assign(&mut self, rhs: Self) {
        self.timestamp *= rhs.timestamp;
        self.mk *= rhs.mk;
        self.is_trigger_bit *= rhs.is_trigger_bit;
        self.breakdown_key *= rhs.breakdown_key;
        self.trigger_value *= rhs.trigger_value;
    }
}

impl SharedValue for ShuffleShare {
    type Storage = <ShuffleShareF as SharedValue>::Storage;

    const BITS: u32 = ShuffleShareF::BITS
        + ShuffleShareMK::BITS
        + ShuffleShareF::BITS
        + ShuffleShareBK::BITS
        + ShuffleShareF::BITS;

    const ZERO: Self = Self {
        timestamp: ShuffleShareF::ZERO,
        mk: ShuffleShareMK::ZERO,
        is_trigger_bit: ShuffleShareF::ZERO,
        breakdown_key: ShuffleShareBK::ZERO,
        trigger_value: ShuffleShareF::ZERO,
    };
}

impl ShuffleShare {
    #[must_use]
    pub fn from_input_row(input_row: &ShuffleInputRow, shared_with: Direction) -> Self {
        match shared_with {
            Direction::Left => Self {
                timestamp: input_row.timestamp.as_tuple().1,
                mk: input_row.mk_shares.as_tuple().1,
                is_trigger_bit: input_row.is_trigger_bit.as_tuple().1,
                breakdown_key: input_row.breakdown_key.as_tuple().1,
                trigger_value: input_row.trigger_value.as_tuple().1,
            },

            Direction::Right => Self {
                timestamp: input_row.timestamp.as_tuple().0,
                mk: input_row.mk_shares.as_tuple().0,
                is_trigger_bit: input_row.is_trigger_bit.as_tuple().0,
                breakdown_key: input_row.breakdown_key.as_tuple().0,
                trigger_value: input_row.trigger_value.as_tuple().0,
            },
        }
    }

    #[must_use]
    pub fn to_input_row(self, rhs: Self) -> ShuffleInputRow {
        ShuffleInputRow {
            timestamp: (self.timestamp, rhs.timestamp).into(),
            mk_shares: (self.mk, rhs.mk).into(),
            is_trigger_bit: (self.is_trigger_bit, rhs.is_trigger_bit).into(),
            breakdown_key: (self.breakdown_key, rhs.breakdown_key).into(),
            trigger_value: (self.trigger_value, rhs.trigger_value).into(),
        }
    }
}

impl rand::prelude::Distribution<ShuffleShare> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ShuffleShare {
        ShuffleShare {
            timestamp: ShuffleShareF::truncate_from(rng.gen::<u128>()),
            mk: ShuffleShareMK::truncate_from(rng.gen::<u128>()),
            is_trigger_bit: ShuffleShareF::truncate_from(rng.gen::<u128>()),
            breakdown_key: ShuffleShareBK::truncate_from(rng.gen::<u128>()),
            trigger_value: ShuffleShareF::truncate_from(rng.gen::<u128>()),
        }
    }
}

impl Add for ShuffleShare {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

impl<'a, 'b> Add<&'b ShuffleShare> for &'a ShuffleShare {
    type Output = ShuffleShare;

    fn add(self, rhs: &'b ShuffleShare) -> Self::Output {
        Self::Output {
            timestamp: self.timestamp + rhs.timestamp,
            mk: self.mk + rhs.mk,
            is_trigger_bit: self.is_trigger_bit + rhs.is_trigger_bit,
            breakdown_key: self.breakdown_key + rhs.breakdown_key,
            trigger_value: self.trigger_value + rhs.trigger_value,
        }
    }
}

impl<'a> Add<ShuffleShare> for &'a ShuffleShare {
    type Output = ShuffleShare;

    fn add(self, rhs: ShuffleShare) -> Self::Output {
        Add::add(self, &rhs)
    }
}
impl Serializable for ShuffleShare {
    type Size = <<ShuffleShareF as Serializable>::Size as Add<
        <<ShuffleShareMK as Serializable>::Size as Add<
            <<ShuffleShareF as Serializable>::Size as Add<
                <<ShuffleShareBK as Serializable>::Size as Add<
                    <ShuffleShareF as Serializable>::Size,
                >>::Output,
            >>::Output,
        >>::Output,
    >>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let mk_sz = <ShuffleShareMK as Serializable>::Size::USIZE;
        let bk_sz = <ShuffleShareBK as Serializable>::Size::USIZE;
        let f_sz = <ShuffleShareF as Serializable>::Size::USIZE;

        self.timestamp
            .serialize(GenericArray::from_mut_slice(&mut buf[..f_sz]));
        self.mk
            .serialize(GenericArray::from_mut_slice(&mut buf[f_sz..f_sz + mk_sz]));
        self.is_trigger_bit.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz..f_sz + mk_sz + f_sz],
        ));
        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz + f_sz..f_sz + mk_sz + f_sz + bk_sz],
        ));
        self.trigger_value.serialize(GenericArray::from_mut_slice(
            &mut buf[f_sz + mk_sz + f_sz + bk_sz..],
        ));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let mk_sz = <ShuffleShareMK as Serializable>::Size::USIZE;
        let bk_sz = <ShuffleShareBK as Serializable>::Size::USIZE;
        let f_sz = <ShuffleShareF as Serializable>::Size::USIZE;

        let timestamp = ShuffleShareF::deserialize(GenericArray::from_slice(&buf[..f_sz]));
        let mk = ShuffleShareMK::deserialize(GenericArray::from_slice(&buf[f_sz..f_sz + mk_sz]));
        let is_trigger_bit = ShuffleShareF::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz..f_sz + mk_sz + f_sz],
        ));
        let breakdown_key = ShuffleShareBK::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz + f_sz..f_sz + mk_sz + f_sz + bk_sz],
        ));
        let trigger_value = ShuffleShareF::deserialize(GenericArray::from_slice(
            &buf[f_sz + mk_sz + f_sz + bk_sz..],
        ));
        Self {
            timestamp,
            mk,
            is_trigger_bit,
            breakdown_key,
            trigger_value,
        }
    }
}
