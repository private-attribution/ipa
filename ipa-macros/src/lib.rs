mod derive_gate;
mod derive_step;
mod parser;
mod tree;
use proc_macro::TokenStream;

#[proc_macro_derive(Gate)]
pub fn derive_gate(item: TokenStream) -> TokenStream {
    derive_gate::expand(item)
}

#[proc_macro_derive(Step, attributes(dynamic))]
pub fn derive_step(input: TokenStream) -> TokenStream {
    derive_step::expand(input)
}
