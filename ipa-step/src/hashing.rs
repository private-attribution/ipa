use std::{
    collections::BTreeMap,
    hash::{DefaultHasher, Hash, Hasher},
};

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote, ToTokens};

use crate::CompactGateIndex;

/// Builds a map of step strings to the corresponding compact gate index. Emits an array of tuples
/// containing the hash and the index, sorted by hash. [`FromStr`] implementation for
/// compact gate uses the same hashing algorithm for input string and uses the provided code to
/// run binary search and find the item.
///
/// The complexity of this operation at compile time is O(n) and the cost is hash(str)*n.
/// Runtime overhead is proportional to hash(str)+log(n).
///
/// ## Hash collisions
/// This currently uses the standard library [`Hasher`] interface to generate hashes that are limited
/// to 8 bytes in size. This means that there is a small chance of hash collisions that increases
/// with the overall increase in number of steps.
///
/// If that happens, a list of potential mitigations include
/// * salt the hash,
/// * use a different hash algorithm
/// * use a perfect hash function.
///
/// The latter may result in more work to be done at runtime, but likely shouldn't impact
/// the latency as long as [`FromStr`] is only used to create HTTP requests.
///
/// This implementation panics if it detects hash collisions.
///
/// [`FromStr`]: std::str::FromStr
pub(crate) struct HashingSteps {
    inner: BTreeMap<u64, CompactGateIndex>,
    type_name: Ident,
}

fn hash(s: &str) -> u64 {
    let mut hasher = DefaultHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

impl HashingSteps {
    pub fn new(gate_type: &Ident) -> Self {
        Self {
            inner: BTreeMap::default(),
            type_name: format_ident!("{}Lookup", gate_type),
        }
    }

    /// Add a step to the map.
    /// ## Panics
    /// if the step already added or if there is a hash collision with any of the steps already
    /// added.
    pub fn hash(&mut self, step: &str, gate: CompactGateIndex) {
        let h = hash(step);
        if let Some(old_val) = self.inner.insert(h, gate) {
            panic!("Hash collision for {step}: {h} => {old_val} and {gate}. Check that there are no duplicate steps defined in the protocol.");
        }
    }

    pub fn lookup_type(&self) -> &Ident {
        &self.type_name
    }
}

impl ToTokens for HashingSteps {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let lookup_type = self.lookup_type();
        let sz = self.inner.len();
        let hashes = self.inner.iter().map(|(h, i)| quote! {(#h, #i)});

        tokens.extend(quote! {
            #lookup_type {
                #[allow(clippy::unreadable_literal)]
                inner: [#(#hashes),*]
            };

            struct #lookup_type {
                inner: [(u64, u32); #sz]
            }

            impl #lookup_type {
                fn find(&self, input: &str) -> Option<u32> {
                    let h = Self::hash(input);
                    self.inner.binary_search_by_key(&h, |(hash, _)| *hash).ok().map(|i| self.inner[i].1)
                }

                /// This must be kept in sync with proc-macro code that generates the hash.
                fn hash(s: &str) -> u64 {
                    let mut hasher = ::std::hash::DefaultHasher::default();
                    ::std::hash::Hash::hash(s, &mut hasher);
                    ::std::hash::Hasher::finish(&hasher)
                }
            }
        });
    }
}
