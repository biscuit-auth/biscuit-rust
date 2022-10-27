//! ```rust
//! use biscuit_auth::KeyPair;
//! use biscuit_quote::{authorizer, biscuit, block};
//! use std::time::{Duration, SystemTime};
//!
//! let root = KeyPair::new();
//!
//! let biscuit = biscuit!(
//!   r#"
//!   user({user_id});
//!   right({user_id}, "file1", "read");
//!   "#,
//!   user_id = "1234",
//! ).build(&root).expect("Failed to create biscuit");
//!
//! let new_biscuit = biscuit.append(block!(
//!   r#"
//!     check if time($time), $time < {expiration};
//!   "#,
//!   expiration = SystemTime::now() + Duration::from_secs(86_400),
//! )).expect("Failed to append block");
//!
//! new_biscuit.authorize(&authorizer!(
//!   r#"
//!      time({now});
//!      operation({operation});
//!      resource({resource});
//!
//!      is_allowed($user_id) <- right($user_id, $resource, $operation),
//!                              resource($resource),
//!                              operation($operation);
//!
//!      allow if is_allowed({user_id});
//!   "#,
//!   now = SystemTime::now(),
//!   operation = "read",
//!   resource = "file1",
//!   user_id = "1234",
//! )).expect("Failed to authorize biscuit");
//! ```

use biscuit_parser::{
    builder::{Check, Fact, Policy, Rule},
    error,
    parser::{parse_block_source, parse_source},
};
use proc_macro2::{Span, TokenStream};
use proc_macro_error::{abort_call_site, proc_macro_error};
use quote::{quote, ToTokens};
use std::collections::{HashMap, HashSet};
use syn::{
    parse::{self, Parse, ParseStream},
    Expr, Ident, LitStr, Token, TypePath,
};

// parses ", foo = bar, baz = quux", including the leading comma
struct ParsedParameters {
    parameters: HashMap<String, Expr>,
}

impl Parse for ParsedParameters {
    fn parse(input: ParseStream) -> parse::Result<Self> {
        let mut parameters = HashMap::new();

        while input.peek(Token![,]) {
            let _: Token![,] = input.parse()?;
            if input.is_empty() {
                break;
            }

            let key: Ident = input.parse()?;
            let _: Token![=] = input.parse()?;
            let value: Expr = input.parse()?;

            parameters.insert(key.to_string(), value);
        }

        Ok(Self { parameters })
    }
}

// parses "\"...\", foo = bar, baz = quux"
struct ParsedCreateNew {
    datalog: String,
    parameters: HashMap<String, Expr>,
}

impl Parse for ParsedCreateNew {
    fn parse(input: ParseStream) -> parse::Result<Self> {
        let datalog = input.parse::<LitStr>()?.value();
        let parameters = input.parse::<ParsedParameters>()?;

        Ok(Self {
            datalog,
            parameters: parameters.parameters,
        })
    }
}

// parses "&mut b, \"...\", foo = bar, baz = quux"
struct ParsedMerge {
    target: Expr,
    datalog: String,
    parameters: HashMap<String, Expr>,
}

impl Parse for ParsedMerge {
    fn parse(input: ParseStream) -> parse::Result<Self> {
        let target = input.parse::<Expr>()?;
        let _: Token![,] = input.parse()?;

        let datalog = input.parse::<LitStr>()?.value();
        let parameters = input.parse::<ParsedParameters>()?;

        Ok(Self {
            target,
            datalog,
            parameters: parameters.parameters,
        })
    }
}

/// Create a `BlockBuilder` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
///
/// ```rust
/// use biscuit_auth::Biscuit;
/// use biscuit_quote::{block};
///
/// let b = block!(
///   r#"
///     user({user_id});
///     check if user($id);
///   "#,
///   user_id = "1234"
/// );
/// ```
#[proc_macro]
#[proc_macro_error]
pub fn block(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedCreateNew {
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedCreateNew);

    let ty = syn::parse_quote!(::biscuit_auth::builder::BlockBuilder);
    let builder = Builder::block_source(ty, None, &datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

/// Merge facts, rules, and checks into a `BlockBuilder` from a datalog
/// string and optional parameters. The datalog string is parsed at compile time
/// and replaced by manual block building.
///
/// ```rust
/// use biscuit_auth::Biscuit;
/// use biscuit_quote::{block, block_merge};
///
/// let mut b = block!(
///   r#"
///     user({user_id});
///   "#,
///   user_id = "1234"
/// );
///
/// block_merge!(
///   &mut b,
///   r#"
///     check if user($id);
///   "#
/// );
/// ```
#[proc_macro]
#[proc_macro_error]
pub fn block_merge(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedMerge {
        target,
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedMerge);

    let ty = syn::parse_quote!(::biscuit_auth::builder::BlockBuilder);
    let builder = Builder::block_source(ty, Some(target), &datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

/// Create an `Authorizer` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
///
/// ```rust
/// use biscuit_quote::{authorizer};
/// use std::time::SystemTime;
///
/// let b = authorizer!(
///   r#"
///     time({now});
///     allow if true;
///   "#,
///   now = SystemTime::now(),
/// );
/// ```
#[proc_macro]
#[proc_macro_error]
pub fn authorizer(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedCreateNew {
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedCreateNew);

    let ty = syn::parse_quote!(::biscuit_auth::Authorizer);
    let builder = Builder::source(ty, None, &datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

/// Merge facts, rules, checks, and policies into an `Authorizer` from a datalog
/// string and optional parameters. The datalog string is parsed at compile time
/// and replaced by manual block building.
///
/// ```rust
/// use biscuit_quote::{authorizer, authorizer_merge};
/// use std::time::SystemTime;
///
/// let mut b = authorizer!(
///   r#"
///     time({now});
///   "#,
///   now = SystemTime::now()
/// );
///
/// authorizer_merge!(
///   &mut b,
///   r#"
///     allow if true;
///   "#
/// );
/// ```
#[proc_macro]
#[proc_macro_error]
pub fn authorizer_merge(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedMerge {
        target,
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedMerge);

    let ty = syn::parse_quote!(::biscuit_auth::Authorizer);
    let builder = Builder::source(ty, Some(target), &datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

/// Create an `BiscuitBuilder` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
///
/// ```rust
/// use biscuit_auth::{Biscuit, KeyPair};
/// use biscuit_quote::{biscuit};
/// use std::time::{SystemTime, Duration};
///
/// let root = KeyPair::new();
/// let biscuit = biscuit!(
///   r#"
///     user({user_id});
///     check if time($time), $time < {expiration}
///   "#,
///   user_id = "1234",
///   expiration = SystemTime::now() + Duration::from_secs(86_400)
/// ).build(&root);
/// ```
#[proc_macro]
#[proc_macro_error]
pub fn biscuit(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedCreateNew {
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedCreateNew);

    let ty = syn::parse_quote!(::biscuit_auth::builder::BiscuitBuilder);
    let builder = Builder::block_source(ty, None, &datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

/// Merge facts, rules, and checks into a `BiscuitBuilder` from a datalog
/// string and optional parameters. The datalog string is parsed at compile time
/// and replaced by manual block building.
///
/// ```rust
/// use biscuit_auth::{Biscuit, KeyPair};
/// use biscuit_quote::{biscuit, biscuit_merge};
/// use std::time::{SystemTime, Duration};
///
/// let root = KeyPair::new();
///
/// let mut b = biscuit!(
///   r#"
///     user({user_id});
///   "#,
///   user_id = "1234"
/// );
///
/// biscuit_merge!(
///   &mut b,
///   r#"
///     check if time($time), $time < {expiration}
///   "#,
///   expiration = SystemTime::now() + Duration::from_secs(86_400)
/// );
///
/// let biscuit = b.build(&root);
/// ```
#[proc_macro]
#[proc_macro_error]
pub fn biscuit_merge(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedMerge {
        target,
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedMerge);

    let ty = syn::parse_quote!(::biscuit_auth::builder::BiscuitBuilder);
    let builder = Builder::block_source(ty, Some(target), &datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

#[derive(Clone, Debug)]
struct Builder {
    pub builder_type: TypePath,
    pub target: Option<Expr>,
    pub parameters: HashMap<String, Expr>,

    // parameters used in the datalog source
    pub datalog_parameters: HashSet<String>,
    // parameters provided to the macro
    pub macro_parameters: HashSet<String>,

    pub facts: Vec<Fact>,
    pub rules: Vec<Rule>,
    pub checks: Vec<Check>,
    pub policies: Vec<Policy>,
}

impl Builder {
    fn new(
        builder_type: TypePath,
        target: Option<Expr>,
        parameters: HashMap<String, Expr>,
    ) -> Self {
        let macro_parameters = parameters.keys().cloned().collect();

        Self {
            builder_type,
            target,
            parameters,

            datalog_parameters: HashSet::new(),
            macro_parameters,

            facts: Vec::new(),
            rules: Vec::new(),
            checks: Vec::new(),
            policies: Vec::new(),
        }
    }

    fn block_source<T: AsRef<str>>(
        builder_type: TypePath,
        target: Option<Expr>,
        source: T,
        parameters: HashMap<String, Expr>,
    ) -> Result<Builder, error::LanguageError> {
        let mut builder = Builder::new(builder_type, target, parameters);
        let source = parse_block_source(source.as_ref())?;

        builder.facts(source.facts.into_iter().map(|(_name, fact)| fact));
        builder.rules(source.rules.into_iter().map(|(_name, rule)| rule));
        builder.checks(source.checks.into_iter().map(|(_name, check)| check));

        builder.validate()?;
        Ok(builder)
    }

    fn source<T: AsRef<str>>(
        builder_type: TypePath,
        target: Option<Expr>,
        source: T,
        parameters: HashMap<String, Expr>,
    ) -> Result<Builder, error::LanguageError> {
        let mut builder = Builder::new(builder_type, target, parameters);
        let source = parse_source(source.as_ref())?;

        builder.facts(source.facts.into_iter().map(|(_name, fact)| fact));
        builder.rules(source.rules.into_iter().map(|(_name, rule)| rule));
        builder.checks(source.checks.into_iter().map(|(_name, check)| check));
        builder.policies(source.policies.into_iter().map(|(_name, policy)| policy));

        builder.validate()?;
        Ok(builder)
    }

    fn facts(&mut self, facts: impl Iterator<Item = Fact>) {
        for fact in facts {
            if let Some(parameters) = &fact.parameters {
                self.datalog_parameters.extend(parameters.keys().cloned());
            }
            self.facts.push(fact);
        }
    }

    fn rule_parameters(&mut self, rule: &Rule) {
        if let Some(parameters) = &rule.parameters {
            self.datalog_parameters.extend(parameters.keys().cloned());
        }

        if let Some(parameters) = &rule.scope_parameters {
            self.datalog_parameters.extend(parameters.keys().cloned());
        }
    }

    fn rules(&mut self, rules: impl Iterator<Item = Rule>) {
        for rule in rules {
            self.rule_parameters(&rule);
            self.rules.push(rule);
        }
    }

    fn checks(&mut self, checks: impl Iterator<Item = Check>) {
        for check in checks {
            for rule in check.queries.iter() {
                self.rule_parameters(rule);
            }
            self.checks.push(check);
        }
    }

    fn policies(&mut self, policies: impl Iterator<Item = Policy>) {
        for policy in policies {
            for rule in policy.queries.iter() {
                self.rule_parameters(rule);
            }
            self.policies.push(policy);
        }
    }

    fn validate(&self) -> Result<(), error::LanguageError> {
        if self.macro_parameters.is_subset(&self.datalog_parameters) {
            Ok(())
        } else {
            let unused_parameters: Vec<String> = self
                .macro_parameters
                .difference(&self.datalog_parameters)
                .cloned()
                .collect();
            Err(error::LanguageError::Parameters {
                missing_parameters: Vec::new(),
                unused_parameters,
            })
        }
    }
}

struct Item {
    parameters: HashSet<String>,
    start: TokenStream,
    middle: TokenStream,
    end: TokenStream,
}

impl Item {
    fn fact(fact: &Fact) -> Self {
        Self {
            parameters: fact
                .parameters
                .iter()
                .flatten()
                .map(|(name, _)| name.to_owned())
                .collect(),
            start: quote! {
                let mut __biscuit_auth_item = #fact;
            },
            middle: TokenStream::new(),
            end: quote! {
                __biscuit_auth_builder.add_fact(__biscuit_auth_item).unwrap();
            },
        }
    }
    fn rule(rule: &Rule) -> Self {
        Self {
            parameters: Item::rule_params(rule).collect(),
            start: quote! {
                let mut __biscuit_auth_item = #rule;
            },
            middle: TokenStream::new(),
            end: quote! {
                __biscuit_auth_builder.add_rule(__biscuit_auth_item).unwrap();
            },
        }
    }

    fn check(check: &Check) -> Self {
        Self {
            parameters: check.queries.iter().flat_map(Item::rule_params).collect(),
            start: quote! {
                let mut __biscuit_auth_item = #check;
            },
            middle: TokenStream::new(),
            end: quote! {
                __biscuit_auth_builder.add_check(__biscuit_auth_item).unwrap();
            },
        }
    }

    fn policy(policy: &Policy) -> Self {
        Self {
            parameters: policy.queries.iter().flat_map(Item::rule_params).collect(),
            start: quote! {
                let mut __biscuit_auth_item = #policy;
            },
            middle: TokenStream::new(),
            end: quote! {
                __biscuit_auth_builder.add_policy(__biscuit_auth_item).unwrap();
            },
        }
    }

    fn rule_params(rule: &Rule) -> impl Iterator<Item = String> + '_ {
        rule.parameters
            .iter()
            .flatten()
            .map(|(name, _)| name.as_ref())
            .chain(
                rule.scope_parameters
                    .iter()
                    .flatten()
                    .map(|(name, _)| name.as_ref()),
            )
            .map(str::to_owned)
    }

    fn needs_param(&self, name: &str) -> bool {
        self.parameters.contains(name)
    }

    fn add_param(&mut self, name: &str, clone: bool) {
        let ident = Ident::new(&name, Span::call_site());

        let expr = if clone {
            quote! { ::core::clone::Clone::clone(&#ident) }
        } else {
            quote! { #ident }
        };

        self.middle.extend(quote! {
            __biscuit_auth_item.set_macro_param(#name, #expr).unwrap();
        });
    }
}

impl ToTokens for Item {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(self.start.clone());
        tokens.extend(self.middle.clone());
        tokens.extend(self.end.clone());
    }
}

impl ToTokens for Builder {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let params_quote = {
            let (ident, expr): (Vec<_>, Vec<_>) = self
                .parameters
                .iter()
                .map(|(name, expr)| {
                    let ident = Ident::new(&name, Span::call_site());
                    (ident, expr)
                })
                .unzip();

            // Bind all parameters "in parallel". If this were a sequence of let bindings,
            // earlier bindings would affect the scope of later bindings.
            quote! {
                let (#(#ident),*) = (#(#expr),*);
            }
        };

        let mut items = self
            .facts
            .iter()
            .map(Item::fact)
            .chain(self.rules.iter().map(Item::rule))
            .chain(self.checks.iter().map(Item::check))
            .chain(self.policies.iter().map(Item::policy))
            .collect::<Vec<_>>();

        for param in &self.datalog_parameters {
            let mut items = items.iter_mut().filter(|i| i.needs_param(param)).peekable();

            loop {
                match (items.next(), items.peek()) {
                    (Some(cur), Some(_next)) => cur.add_param(&param, true),
                    (Some(cur), None) => cur.add_param(&param, false),
                    (None, _) => break,
                }
            }
        }

        let builder_type = &self.builder_type;
        let builder_quote = if let Some(target) = &self.target {
            quote! {
                let __biscuit_auth_builder: &mut #builder_type = #target;
            }
        } else {
            quote! {
                let mut __biscuit_auth_builder = <#builder_type>::new();
            }
        };

        tokens.extend(quote! {
            {
                #builder_quote
                #params_quote
                #(#items)*
                __biscuit_auth_builder
            }
        });
    }
}
