// This module exists here because all of this functionality cannot be exported
// from the ipa-step-derive proc-macro crate.  It is only used by build scripts.

use std::{collections::HashMap, env, fs::write, path::PathBuf};

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, parse_str, Ident, Path};

use crate::{hash::HashingSteps, name::GateName, CompactGateIndex, CompactStep};

fn crate_path(p: &str) -> String {
    let Some((_, p)) = p.split_once("::") else {
        panic!("unable to handle name of type `{p}`");
    };
    String::from("crate::") + p
}

/// Implement `StepNarrow` for each of the child types in the tree of steps.
fn build_narrows(
    ident: &Ident,
    gate_name: &str,
    step_narrows: HashMap<&str, Vec<CompactGateIndex>>,
    syntax: &mut TokenStream,
) {
    for (t, steps) in step_narrows {
        let t = crate_path(t);
        let ty: Path = parse_str(&t).unwrap();
        let short_name = t.rsplit_once("::").map_or_else(|| t.as_ref(), |(_a, b)| b);
        let msg = format!("unexpected narrow for {gate_name}({{s}}) => {short_name}({{ss}})");
        syntax.extend(quote! {
            #[allow(clippy::too_many_lines, clippy::unreadable_literal)]
            impl ::ipa_step::StepNarrow<#ty> for #ident {
                fn narrow(&self, step: &#ty) -> Self {
                    match self.0 {
                        #(#steps)|* => Self(self.0 + 1 + <#ty as ::ipa_step::CompactStep>::base_index(step)),
                        _ => panic!(#msg,
                                    s = self.as_ref(),
                                    ss = <#ty as ::std::convert::AsRef<str>>::as_ref(step)),
                    }
                }
            }
        });
    }
}

/// Write code for the `CompactGate` implementation related to `S` to the determined file.
/// # Panics
/// For various reasons when the type of `S` takes a form that is surprising.
pub fn build<S: CompactStep>() {
    let step_name = crate_path(std::any::type_name::<S>());
    let Some((_, name)) = step_name.rsplit_once("::") else {
        panic!("unable to handle name of type `{step_name}`");
    };
    let name_maker = GateName::new(name);
    let gate_name = name_maker.name();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join(name_maker.filename());
    println!("writing Gate implementation {gate_name} (for {step_name}) to {out:?}");
    let gate_impl = compact_gate_impl::<S>(&gate_name);

    write(out, prettyplease::unparse(&parse2(gate_impl).unwrap())).unwrap();
}

fn compact_gate_impl<S: CompactStep>(gate_name: &str) -> TokenStream {
    let ident: Ident = parse_str(gate_name).unwrap();

    let mut step_narrows = HashMap::new();
    step_narrows.insert(std::any::type_name::<S>(), vec![0]); // Add the first step.

    let step_count = usize::try_from(S::STEP_COUNT).unwrap();
    // this is an array of gate names indexed by the compact gate index.
    let mut gate_names = Vec::with_capacity(step_count);
    // builds a lookup table for steps to resolve them to the compact gate index.
    let mut step_hasher = HashingSteps::new(&ident);

    for i in 1..=S::STEP_COUNT {
        let s = String::from("/") + &S::step_string(i - 1);
        step_hasher.hash(&s, i);
        gate_names.push(s);

        if let Some(t) = S::step_narrow_type(i - 1) {
            step_narrows.entry(t).or_insert_with(Vec::new).push(i);
        }
    }

    let from_panic = format!("unknown string for {gate_name}: \"{{s}}\"");
    let gate_lookup_type = step_hasher.lookup_type();
    let mut syntax = quote! {

        #[allow(clippy::unreadable_literal)]
        static STR_LOOKUP: [&str; #step_count] = [#(#gate_names),*];
        static GATE_LOOKUP: #gate_lookup_type = #step_hasher

        impl ::std::convert::AsRef<str> for #ident {
            fn as_ref(&self) -> &str {
                match usize::try_from(self.0).unwrap() {
                    0 => "/",
                    i => STR_LOOKUP[i - 1],
                }
            }
        }

        impl ::std::str::FromStr for #ident {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if s == "/" {
                    Ok(Self::default())
                } else {
                    GATE_LOOKUP.find(s).map(#ident).ok_or_else(|| format!(#from_panic))
                }
            }
        }

        impl ::std::convert::From<&str> for #ident {
            fn from(s: &str) -> Self {
                <Self as ::std::str::FromStr>::from_str(s).unwrap_or_else(|e| panic!("{e}"))
            }
        }
    };
    build_narrows(&ident, gate_name, step_narrows, &mut syntax);

    syntax
}

#[cfg(test)]
mod test {
    use crate::{CompactGateIndex, CompactStep, Step};

    struct HashCollision;

    impl Step for HashCollision {}

    impl AsRef<str> for HashCollision {
        fn as_ref(&self) -> &str {
            std::any::type_name::<Self>()
        }
    }

    impl CompactStep for HashCollision {
        const STEP_COUNT: CompactGateIndex = 2;

        fn base_index(&self) -> CompactGateIndex {
            0
        }

        fn step_string(_i: CompactGateIndex) -> String {
            "same-step".to_string()
        }
    }

    #[test]
    #[should_panic(expected = "Hash collision for /same-step")]
    fn panics_on_hash_collision() {
        super::compact_gate_impl::<HashCollision>("Gate");
    }
}
