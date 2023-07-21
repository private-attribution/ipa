mod derive_gate;
mod parser;
mod step;
mod tree;
use proc_macro::TokenStream;

#[proc_macro_derive(Gate)]
pub fn derive_gate(item: TokenStream) -> TokenStream {
    derive_gate::expand(item)
}

#[proc_macro_attribute]
pub fn step(attr: TokenStream, input: TokenStream) -> TokenStream {
    step::expand(attr, input)
}
