use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    meta::ParseNestedMeta, spanned::Spanned, Attribute, DataEnum, ExprPath, Fields, Ident, LitInt,
    LitStr, Type, TypePath, Variant,
};

use crate::{sum::ExtendedSum, CaseStyle, IntoSpan};

struct VariantAttrParser<'a> {
    ident: &'a Ident,
    name: Option<String>,
    count: Option<usize>,
    child: Option<ExprPath>,
    integer: Option<TypePath>,
}

impl<'a> VariantAttrParser<'a> {
    fn new(ident: &'a Ident) -> Self {
        Self {
            ident,
            name: None,
            count: None,
            child: None,
            integer: None,
        }
    }

    fn parse(mut self, variant: &Variant) -> Result<VariantAttribute, syn::Error> {
        match &variant.fields {
            Fields::Named(_) => {
                return variant
                    .fields
                    .error("#[derive(CompactStep)] does not support named field");
            }
            Fields::Unnamed(f) => {
                if f.unnamed.len() != 1 {
                    return variant
                        .fields
                        .error("#[derive(CompactStep) only supports empty or integer variants");
                }
                let Some(f) = f.unnamed.first() else {
                    return self.make_attr();
                };

                let Type::Path(int_type) = &f.ty else {
                    return f.ty.span().error(
                        "#[derive(CompactStep)] variants need to have a single integer type",
                    );
                };
                self.integer = Some(int_type.clone());

                // Note: it looks like validating that the target type is an integer is
                // close to impossible, so we'll leave things in this state.
                // We use `TryFrom` for the value, so that will fail at least catch
                // any errors.  The only problem being that the errors will be inscrutable.
            }
            Fields::Unit => {}
        }
        if let Some((_, d)) = &variant.discriminant {
            return d
                .span()
                .error("#[derive(CompactStep)] does not work with discriminants");
        }

        let Some(attr) = variant.attrs.iter().find(|a| a.path().is_ident("step")) else {
            return self.make_attr();
        };

        self.parse_attr(attr)?;
        self.make_attr()
    }

    fn parse_attr(&mut self, attr: &Attribute) -> Result<(), syn::Error> {
        attr.parse_nested_meta(|m| {
            if m.path.is_ident("count") {
                self.parse_count(&m)?;
            } else if m.path.is_ident("name") {
                self.parse_name(&m)?;
            } else if m.path.is_ident("child") {
                self.parse_child(&m)?;
            } else {
                return Err(m.error("#[step(...)] unsupported argument"));
            }
            Ok(())
        })
    }

    fn parse_count(&mut self, m: &ParseNestedMeta<'_>) -> Result<(), syn::Error> {
        if self.count.is_some() {
            return Err(m.error("#[step(count = ...)] duplicated"));
        }
        if self.integer.is_none() {
            return Err(m.error("#[step(count = ...)] only applies to integer variants"));
        }

        let v: LitInt = m.value()?.parse()?;
        let Ok(v) = v.base10_parse::<usize>() else {
            return v.span().error("#[step(count = ...) invalid value");
        };

        if !(2..1000).contains(&v) {
            return v
                .span()
                .error("#[step(count = ...)] needs to be at least 2 and less than 1000");
        }

        self.count = Some(v);
        Ok(())
    }

    fn parse_name(&mut self, m: &ParseNestedMeta<'_>) -> Result<(), syn::Error> {
        if self.name.is_some() {
            return Err(m.error("#[step(name = ...)] duplicated"));
        }

        self.name = Some(m.value()?.parse::<LitStr>()?.value());
        Ok(())
    }

    fn parse_child(&mut self, m: &ParseNestedMeta<'_>) -> Result<(), syn::Error> {
        if self.child.is_some() {
            return Err(m.error("#[step(child = ...)] duplicated"));
        }

        self.child = Some(m.value()?.parse::<ExprPath>()?);
        Ok(())
    }

    fn make_attr(self) -> Result<VariantAttribute, syn::Error> {
        if self.integer.is_some() && self.count.is_none() {
            self.ident.span().error(
                "#[derive(CompactStep)] requires that integer variants include #[step(count = ...)]",
            )
        } else {
            Ok(VariantAttribute {
                ident: self.ident.clone(),
                name: self
                    .name
                    .unwrap_or_else(|| self.ident.to_string().to_snake_case()),
                integer: self.count.zip(self.integer),
                child: self.child,
            })
        }
    }
}

pub struct VariantAttribute {
    ident: Ident,
    name: String,
    integer: Option<(usize, TypePath)>,
    child: Option<ExprPath>,
}

impl VariantAttribute {
    /// Parse a set of attributes out from a representation of an enum.
    pub fn parse_attrs(data: &DataEnum) -> Result<Vec<Self>, syn::Error> {
        let mut steps = Vec::with_capacity(data.variants.len());
        for v in &data.variants {
            steps.push(VariantAttrParser::new(&v.ident).parse(v)?);
        }
        Ok(steps)
    }

    /// Generate the code for a single variant.
    /// Return the updated running tally of steps involved.
    pub fn generate(
        &self,
        arm_count: ExtendedSum,
        name_arrays: &mut TokenStream,
        as_ref_arms: &mut TokenStream,
        step_string_arms: &mut TokenStream,
    ) -> ExtendedSum {
        if self.integer.is_none() {
            self.generate_single(arm_count, as_ref_arms, step_string_arms)
        } else {
            self.generate_int(&arm_count, name_arrays, as_ref_arms, step_string_arms)
        }
    }

    fn generate_single(
        &self,
        mut arm_count: ExtendedSum,
        as_ref_arms: &mut TokenStream,
        step_string_arms: &mut TokenStream,
    ) -> ExtendedSum {
        let VariantAttribute {
            ident: step_ident,
            name: step_name,
            integer: None,
            child: step_child,
        } = self
        else {
            unreachable!();
        };

        as_ref_arms.extend(quote! {
            Self::#step_ident => #step_name,
        });

        step_string_arms.extend(quote! {
            _ if i == #arm_count => Self::#step_ident.as_ref().to_owned(),
        });
        arm_count = arm_count + 1;
        if let Some(child) = step_child {
            let range_end = arm_count.clone()
                + quote!(<#child as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT);
            step_string_arms.extend(quote! {
            _ if i < #range_end => Self::#step_ident.as_ref().to_owned() + "/" +
              &<#child as ::ipa_core::protocol::step::CompactStep>::step_string(i - (#arm_count)),
        });
            range_end
        } else {
            arm_count
        }
    }

    fn generate_int(
        &self,
        arm_count: &ExtendedSum,
        name_arrays: &mut TokenStream,
        as_ref_arms: &mut TokenStream,
        step_string_arms: &mut TokenStream,
    ) -> ExtendedSum {
        let VariantAttribute {
            ident: step_ident,
            name: step_name,
            integer: Some((step_count, step_integer)),
            child: step_child,
        } = self
        else {
            unreachable!();
        };

        let array_name = format_ident!("{}_NAMES", step_ident.to_string().to_shouting_case());
        let skip_zeros = match *step_count - 1 {
            1..=9 => 2,
            10..=99 => 1,
            100..=999 => 0,
            _ => unreachable!("step count is too damn high {step_count}"),
        };
        let step_names =
            (0..*step_count).map(|s| step_name.clone() + &format!("{s:03}")[skip_zeros..]);
        name_arrays.extend(quote! {
            const #array_name: [&str; #step_count] = [#(#step_names),*];
        });
        as_ref_arms.extend(quote! {
             Self::#step_ident(i) => #array_name[usize::try_from(*i).unwrap()],
        });

        if let Some(child) = step_child {
            let full_count = *step_count + 1;
            let range_end = arm_count.clone()
                + quote!((<#child as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT * #full_count));
            step_string_arms.extend(quote! {
                _ if i < #range_end => {
                    let offset = i - (#arm_count);
                    let divisor = <#child as ::ipa_core::protocol::step::CompactStep>::STEP_COUNT + 1;
                    let s = Self::#step_ident(#step_integer::try_from(offset / divisor).unwrap()).as_ref().to_owned();
                    if let Some(v) = (offset % divisor).checked_sub(1) {
                        s + "/" + &<#child as ::ipa_core::protocol::step::CompactStep>::step_string(v)
                    } else {
                        s
                    }
               }
           });
            range_end
        } else {
            let range_end = arm_count.clone() + *step_count;
            step_string_arms.extend(quote! {
            _ if i < #range_end => Self::#step_ident(#step_integer::try_from(i - (#arm_count)).unwrap()).as_ref().to_owned(),
        });
            range_end
        }
    }
}
