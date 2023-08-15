use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

use crate::parser::{group_by_modules, ipa_state_transition_map};

/// Generate a state transition graph and the corresponding `AsRef<str>`
/// and `deserialize()` implementations for `Compact` gate.

pub fn expand(item: TokenStream) -> TokenStream {
    // `item` is the `struct Compact(u16)` in AST
    let ast = parse_macro_input!(item as DeriveInput);
    let gate = &ast.ident;
    match &ast.data {
        syn::Data::Struct(_) => {}
        _ => panic!("derive Gate expects a struct"),
    }

    let mut expanded = quote!(
        impl crate::protocol::step::Step for #gate {}
    );

    let steps = ipa_state_transition_map();
    let grouped_steps = group_by_modules(&steps);
    let mut reverse_map = Vec::new();
    let mut deserialize_map = Vec::new();

    for (_, steps) in grouped_steps {
        // generate the reverse map for `impl AsRef<str> for Compact`
        // this is used to convert a state ID to a string representation of the state.
        reverse_map.extend(steps.iter().map(|s| {
            let path = &s.path;
            let state_id = s.id;
            quote!(
                #state_id => #path,
            )
        }));

        deserialize_map.extend(steps.iter().map(|s| {
            let path = &s.path;
            let state_id = s.id;
            quote!(
                #path => #state_id,
            )
        }));
    }

    expanded.extend(quote!(
        impl AsRef<str> for #gate {
            fn as_ref(&self) -> &str {
                match self.0 {
                    #(#reverse_map)*
                    _ => static_reverse_state_map(self.0),
                }
            }
        }
    ));

    // replace `u16` with the type acquired from the AST
    expanded.extend(
        quote!(
            impl Compact {
                pub fn deserialize(s: &str) -> Compact {
                    Self(match s {
                        #(#deserialize_map)*
                        _ => static_deserialize_state_map(s),
                    })
                }
            }
        )
        .into_iter(),
    );

    expanded.into()
}
