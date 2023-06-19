mod derive_gate;
mod tree;
use proc_macro::TokenStream;

#[proc_macro_derive(Gate)]
pub fn derive_gate(item: TokenStream) -> TokenStream {
    derive_gate::expand(item)
}
