pub mod convert_shares;

// TODO: wean usage off convert_some_bits.
pub(crate) use convert_shares::convert_some_bits;
pub use convert_shares::{
    convert_bits, BitConversionTriple, LocalBitConverter, ToBitConversionTriples,
};
