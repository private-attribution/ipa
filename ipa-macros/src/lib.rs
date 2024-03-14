mod derive_step;
use proc_macro::TokenStream;

#[proc_macro_derive(Step, attributes(dynamic))]
pub fn derive_step(input: TokenStream) -> TokenStream {
    derive_step::expand(input)
}
