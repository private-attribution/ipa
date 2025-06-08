use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    ops::{Add, AddAssign},
};

use proc_macro2::{
    Delimiter, Punct, Spacing, Span, TokenStream, TokenTree,
    token_stream::IntoIter as TokenTreeIter,
};
use quote::{ToTokens, TokenStreamExt, quote};
use syn::{Ident, LitStr, Visibility, parse::Parser, parse2, token::Pub};

use crate::IntoSpan;

/// The path to a module, which is a series of identifiers (separated by '::').
/// e.g., `path::to::a::module`
#[derive(Clone, PartialEq, Eq, Hash)]
struct ModulePath {
    path: Vec<Ident>,
}

impl ModulePath {
    fn new() -> Self {
        Self { path: Vec::new() }
    }

    fn len(&self) -> usize {
        self.path.len()
    }

    fn is_empty(&self) -> bool {
        self.path.is_empty()
    }

    /// Determine if this path is a prefix of the other.
    fn is_prefix(&self, other: &Self) -> bool {
        (self.len() < other.len()) && self.path.iter().eq(other.path.iter().take(self.len()))
    }

    fn ident(&self, idx: usize) -> &Ident {
        &self.path[idx]
    }
}

impl ToTokens for ModulePath {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        for (i, label) in self.path.iter().enumerate() {
            if i > 0 {
                tokens.append(Punct::new(':', Spacing::Joint));
                tokens.append(Punct::new(':', Spacing::Alone));
            }
            tokens.append(label.clone());
        }
    }
}

impl Display for ModulePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("src/")?;
        for (i, label) in self.path.iter().enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            label.fmt(f)?;
        }
        f.write_str(".rs")
    }
}

impl Add<Ident> for &ModulePath {
    type Output = ModulePath;
    fn add(self, rhs: Ident) -> Self::Output {
        let mut p = self.clone();
        p.path.push(rhs);
        p
    }
}

impl AddAssign<Ident> for ModulePath {
    fn add_assign(&mut self, rhs: Ident) {
        self.path.push(rhs);
    }
}

/// This contains a collection of module paths, each with a matching string.
/// It also contains a function name into which the work it performs will be collected.
struct StepModules {
    name: Ident,
    map: HashMap<ModulePath, String>,
}

impl StepModules {
    fn new(name: Ident) -> Self {
        Self {
            name,
            map: HashMap::new(),
        }
    }

    fn insert(&mut self, path: ModulePath) {
        let s = path.to_string();
        self.map.insert(path, s);
    }

    /// The inner loop of the parsing picks up after an ident has been read.
    /// An ident can be followed by:
    /// * Another identifier: `::ident`
    /// * A file location: `@ "file/path.rs"`
    /// * A grouping: `{ident ...}`
    ///
    /// This returns whether a comma should be expected.
    fn parse_inner(&mut self, mut path: ModulePath, tokens: &mut TokenTreeIter) -> syn::Result<()> {
        while let Some(t) = tokens.next() {
            let next = match t {
                TokenTree::Punct(p) => match p.as_char() {
                    ':' => {
                        if p.spacing() != Spacing::Joint {
                            return p.error("expected '::'");
                        }
                        skip_lone_colon(tokens)?;
                        let Some(t) = tokens.next() else {
                            return p.error("unterminated expression after '::'");
                        };
                        t
                    }
                    ',' => {
                        self.insert(path);
                        return Ok(());
                    }
                    '@' => {
                        let s = tokens.next();
                        let s = s.ok_or_else(|| p.raw_err("expected string after '@'"))?;
                        let s: LitStr = parse2(TokenStream::from(s))?;
                        self.map.insert(path, s.value());
                        maybe_skip_comma(tokens)?;
                        return Ok(());
                    }
                    _ => return p.error("expected '::', '@', '{', or ','"),
                },
                _ => return t.error("expected '::', '@', '{', or ','"),
            };

            match next {
                TokenTree::Ident(label) => {
                    path += label;
                }
                TokenTree::Group(g) => {
                    if !matches!(g.delimiter(), Delimiter::Brace) {
                        return g.error("expected a braced grouping");
                    }
                    self.parse_group(&path, g.stream().into_iter())?;
                    maybe_skip_comma(tokens)?;
                    return Ok(());
                }
                _ => return next.error("expected either a label of a braced grouping"),
            }
        }
        self.insert(path);
        Ok(())
    }

    fn parse_group(
        &mut self,
        base_path: &ModulePath,
        mut tokens: TokenTreeIter,
    ) -> syn::Result<()> {
        while let Some(t) = tokens.next() {
            let TokenTree::Ident(label) = t else {
                return t.error("missing a label");
            };

            self.parse_inner(base_path + label, &mut tokens)?;
        }
        Ok(())
    }
}

impl Parser for StepModules {
    type Output = Self;

    fn parse2(mut self, tokens: TokenStream) -> syn::Result<Self::Output> {
        self.parse_group(&ModulePath::new(), tokens.into_iter())?;
        Ok(self)
    }
}

impl ToTokens for StepModules {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let fn_name = &self.name;
        let filenames = self.map.values();
        let modules = ModuleTokens {
            prefix: &ModulePath::new(),
            paths: &self.map,
        };
        tokens.extend(quote! {
            #modules
            fn #fn_name() {
                assert!(
                    ::std::env::var(::ipa_step::COMPACT_GATE_INCLUDE_ENV).is_err(),
                    "setting `{e}` in the environment will cause build errors",
                    e = ::ipa_step::COMPACT_GATE_INCLUDE_ENV
                );
                println!("cargo:rustc-env={e}=true", e = ::ipa_step::COMPACT_GATE_INCLUDE_ENV);
                for f in [#(#filenames),*] {
                    println!("cargo:rerun-if-changed={f}");
                }
            }
        });
    }
}

struct ModuleTokens<'p, 'm> {
    prefix: &'p ModulePath,
    paths: &'m HashMap<ModulePath, String>,
}

impl ToTokens for ModuleTokens<'_, '_> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        // If this is a leaf, then there will be a string value.
        if let Some(s) = self.paths.get(self.prefix) {
            tokens.extend(quote!(include!(#s);));
            return;
        }

        // Otherwise, we are adding modules.
        let idx = self.prefix.len();
        let mut used = HashSet::new();
        for label in self
            .paths
            .keys()
            .filter(|&k| self.prefix.is_prefix(k))
            .map(|k| k.ident(idx))
        {
            if used.contains::<Ident>(label) {
                continue;
            }

            let prefix = self.prefix + label.clone();
            // note: this is not `Self`: different lifetimes
            let inner_tokens = ModuleTokens {
                prefix: &prefix,
                paths: self.paths,
            };
            let exposure = if self.prefix.is_empty() {
                TokenStream::new()
            } else {
                Visibility::Public(Pub {
                    span: Span::call_site(),
                })
                .into_token_stream()
            };
            tokens.extend(quote! {
                #exposure mod #label {
                    #inner_tokens
                }
            });
            used.insert(label.clone());
        }
    }
}

fn maybe_skip_comma(tokens: &mut TokenTreeIter) -> syn::Result<()> {
    let token = tokens.next();
    if let Some(TokenTree::Punct(p)) = token {
        if p.as_char() == ',' && p.spacing() == Spacing::Alone {
            Ok(())
        } else {
            p.error("expecting a comma after each item")
        }
    } else {
        Ok(())
    }
}

fn skip_lone_colon(tokens: &mut TokenTreeIter) -> syn::Result<()> {
    let colon = tokens.next();
    if let Some(TokenTree::Punct(p)) = colon {
        if p.as_char() == ':' && p.spacing() == Spacing::Alone {
            Ok(())
        } else {
            p.error("expecting a colon here")
        }
    } else {
        colon.error("expecting a colon here")
    }
}

pub fn track_steps_impl(input: TokenStream) -> syn::Result<TokenStream> {
    let mut tokens = input.into_iter();
    let fn_name = tokens.next();
    let Some(TokenTree::Ident(fn_name)) = fn_name else {
        return fn_name.error("first token needs to be a function name");
    };
    skip_lone_colon(&mut tokens)?;

    let steps = StepModules::new(fn_name).parse2(tokens.collect::<TokenStream>())?;
    Ok(steps.into_token_stream())
}
