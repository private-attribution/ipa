use std::collections::BTreeMap;

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote, ToTokens};
use syn::{parse_str, Path};

use crate::{CompactGateIndex, StepHasher};

/// Builds a map of step strings to the corresponding compact gate index. Emits an array of tuples
/// containing the hash and the index, sorted by hash. [`FromStr`] implementation for
/// compact gate uses the same hashing algorithm for input string and uses the provided code to
/// run binary search and find the item.
///
/// The complexity of this operation at compile time is O(n) and the cost is hash(str)*n.
/// Runtime overhead is proportional to hash(str)+log(n).
///
pub(crate) struct HashingSteps {
    inner: BTreeMap<u64, CompactGateIndex>,
    type_name: Ident,
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
        let h = step.hash_step();
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
        let hasher_path: Path = parse_str(
            std::any::type_name::<dyn StepHasher>()
                .strip_prefix("dyn ")
                .expect("typename for traits returns the path with dyn prefix"),
        )
        .unwrap();

        tokens.extend(quote! {
            #lookup_type {
                #[allow(clippy::unreadable_literal)]
                inner: [#(#hashes),*]
            };

            struct #lookup_type {
                #[allow(clippy::unreadable_literal)]
                inner: [(u64, u32); #sz]
            }

            impl #lookup_type {
                fn find(&self, input: &str) -> Option<u32> {
                    use #hasher_path;
                    let h = input.hash_step();
                    self.inner.binary_search_by_key(&h, |(hash, _)| *hash).ok().map(|i| self.inner[i].1)
                }
            }
        });
    }
}
