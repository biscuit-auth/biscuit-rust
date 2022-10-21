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

extern crate proc_macro;
extern crate proc_macro_error;
use biscuit_parser::{
    builder::{Check, Fact, Policy, Rule},
    error,
    parser::{parse_block_source, parse_source},
};
use proc_macro::TokenStream;
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
pub fn block(input: TokenStream) -> TokenStream {
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
pub fn block_merge(input: TokenStream) -> TokenStream {
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
pub fn authorizer(input: TokenStream) -> TokenStream {
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
pub fn authorizer_merge(input: TokenStream) -> TokenStream {
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
pub fn biscuit(input: TokenStream) -> TokenStream {
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
pub fn biscuit_merge(input: TokenStream) -> TokenStream {
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

    pub fn block_source<T: AsRef<str>>(
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

    pub fn source<T: AsRef<str>>(
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
        if self.datalog_parameters == self.macro_parameters {
            Ok(())
        } else {
            let unused_parameters: Vec<String> = self
                .macro_parameters
                .difference(&self.datalog_parameters)
                .cloned()
                .collect();
            let missing_parameters: Vec<String> = self
                .datalog_parameters
                .difference(&self.macro_parameters)
                .cloned()
                .collect();
            Err(error::LanguageError::Parameters {
                missing_parameters,
                unused_parameters,
            })
        }
    }
}

impl ToTokens for Builder {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let (param_names, param_values): (Vec<String>, Vec<Expr>) =
            self.parameters.clone().into_iter().unzip();

        let facts_quote = self.facts.iter().map(|f| {
            quote! {
                let mut fact = #f;
                #(fact.set_macro_param(#param_names, #param_values).unwrap();)*
                builder.add_fact(fact).unwrap();
            }
        });

        let rules_quote = self.rules.iter().map(|r| {
            quote! {
                let mut rule = #r;
                #(rule.set_macro_param(#param_names, #param_values).unwrap();)*
                builder.add_rule(rule).unwrap();
            }
        });

        let checks_quote = self.checks.iter().map(|c| {
            quote! {
                let mut check = #c;
                #(check.set_macro_param(#param_names, #param_values).unwrap();)*
                builder.add_check(check).unwrap();
            }
        });

        let policies_quote = self.policies.iter().map(|p| {
            quote! {
                let mut policy = #p;
                #(policy.set_macro_param(#param_names, #param_values).unwrap();)*
                builder.add_policy(policy).unwrap();
            }
        });

        let builder_type = &self.builder_type;
        let builder_quote = if let Some(target) = &self.target {
            quote! {
                let builder: &mut #builder_type = #target;
            }
        } else {
            quote! {
                let mut builder = <#builder_type>::new();
            }
        };

        tokens.extend(quote! {
            {
                #builder_quote
                #(#facts_quote)*
                #(#rules_quote)*
                #(#checks_quote)*
                #(#policies_quote)*
                builder
            }
        });
    }
}
