//! Vectorized secret shares
//!
//! Vectorization refers to adapting an implementation that previously operated on one value at a
//! time, to instead operate on `N` values at a time. Vectorization improves performance in two ways:
//!
//!  1. Vectorized code can make use of special CPU instructions (Intel AVX, ARM NEON) that operate
//!     on multiple values at a time. This reduces the CPU time required to perform computations.
//!     We also use vectorization to refer to "bit packing" of boolean values, i.e., packing
//!     64 boolean values into a single u64 rather than using a byte (or even a word) for each
//!     value.
//!  2. Aside from the core arithmetic operations that are involved in our MPC, a substantial
//!     amount of other code is needed to send values between helpers, schedule futures for
//!     execution, etc. Vectorization can result in a greater amount of arithmetic work being
//!     performed for a given amount of overhead work, thus increasing the efficiency of the
//!     implementation.
//!
//! ## Vectorization traits
//!
//! There are two sets of traits related to vectorization.
//!
//! If you are writing protocols, the trait of interest is `FieldSimd<N>`, which can be specified in
//! a trait bound, something like `F: Field + FieldSimd<N>`.
//!
//! The other traits are `Vectorizable` (for `SharedValue`s) and `FieldVectorizable`. These traits
//! are needed to work around a limitation in the rust type system. In most cases, you do not need
//! to reference the `Vectorizable` or `FieldVectorizable` traits directly when implementing
//! protocols. Usually the vector type is hidden within `AdditiveShare`, but if you are writing a
//! vectorized low-level primitive, you may need to refer to it directly, as `<S as
//! Vectorizable<N>>::Array`. It is even more rare to need to use `FieldVectorizable`; see its
//! documentation and the documentation of `FieldSimd` for details.
//!
//! We require that each supported vectorization configuration (i.e. combination of data type and
//! width) be explicitly identified, by implementing the `Vectorizable` and/or `FieldVectorizable`
//! traits for base data type (e.g. `Fp32BitPrime`). This is for two reasons:
//!  1. Rust doesn't yet support evaluating expressions involving const parameters at compile time,
//!     which makes it difficult or impossible to write generic serialization routines for
//!     arbitrary widths.
//!  2. As a measure of protection against inadvertently using a configuration that will not be
//!     efficient (i.e. an excessive vector width).
//!
//! ## Adding a new supported vectorization
//!
//! To add a new supported vectorization:
//!
//!  1. Add `FromRandom` impl (in `array.rs` or `boolean_array.rs`)
//!  2. Add `Serializable` impl (in `array.rs` or `boolean_array.rs`)
//!  3. Add `FieldSimd` impl (in `secret_sharing/vector/impls.rs`)
//!  4. Add `Vectorizable` and `FieldVectorizable` impls (either with the primitive type def in
//!     e.g. `galois_field.rs`, or in `vector/impls.rs`)

mod array;
mod impls;
mod traits;
mod transpose;

pub use array::StdArray;
pub use traits::{FieldArray, FieldSimd, FieldVectorizable, SharedValueArray, Vectorizable};
pub use transpose::TransposeFrom;
#[cfg(feature = "enable-benches")]
pub use transpose::{transpose_16x16, transpose_8x8};
