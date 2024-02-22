use std::ops::Add;

use proc_macro2::{Literal, Punct, Spacing, TokenStream};
use quote::ToTokens;

/// A complex sum, comprised of multiple statements, plus a simple counter.
/// This implements `ToTokens` so that it can be dropped into `quote!()` easily.
#[derive(Default, Clone)]
pub struct ExtendedSum {
    expr: TokenStream,
    extra: usize,
}

impl ToTokens for ExtendedSum {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        if self.expr.is_empty() {
            Literal::usize_suffixed(self.extra).to_tokens(tokens);
        } else {
            tokens.extend(self.expr.clone());
            if self.extra > 0 {
                Punct::new('+', Spacing::Alone).to_tokens(tokens);
                Literal::usize_suffixed(self.extra).to_tokens(tokens);
            }
        }
    }
}

impl Add<usize> for ExtendedSum {
    type Output = Self;
    fn add(self, v: usize) -> Self {
        Self {
            expr: self.expr,
            extra: self.extra + v,
        }
    }
}

impl Add<TokenStream> for ExtendedSum {
    type Output = Self;
    fn add(mut self, v: TokenStream) -> Self {
        if !self.expr.is_empty() {
            Punct::new('+', Spacing::Alone).to_tokens(&mut self.expr);
        }
        self.expr.extend(v);
        Self {
            expr: self.expr,
            extra: self.extra,
        }
    }
}
