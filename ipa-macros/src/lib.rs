mod derive_gate;
mod derive_step;
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

#[proc_macro_derive(Step, attributes(dynamic, obsolete))]
pub fn derive_step(input: TokenStream) -> TokenStream {
    derive_step::expand(input)
}
