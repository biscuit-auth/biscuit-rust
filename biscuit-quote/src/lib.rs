//! ```rust
//! extern crate biscuit_auth;
//! extern crate biscuit_quote;
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
use proc_macro_error::{abort, abort_call_site, proc_macro_error};
use quote::{quote, ToTokens};
use std::collections::{HashMap, HashSet};
use syn::{
    parse::{Parse, ParseStream, Result},
    Expr, Ident, LitStr, Token,
};

/// create a `BlockBuilder` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
///
/// ```rust
/// extern crate biscuit_auth;
/// extern crate biscuit_quote;
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
    let ParsedQuery {
        datalog,
        parameters,
    } = syn::parse(input).unwrap_or_else(|e| abort!(e));

    let builder = BlockBuilderWithParams::from_code(&datalog, &parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    let gen = quote! {
        {
          #builder
        }
    };

    gen.into()
}

struct ParsedQuery {
    datalog: String,
    parameters: HashMap<String, Expr>,
}

impl Parse for ParsedQuery {
    fn parse(input: ParseStream) -> Result<Self> {
        let datalog = input.parse::<LitStr>()?.value();

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

        Ok(ParsedQuery {
            datalog,
            parameters,
        })
    }
}

#[derive(Clone, Debug)]
struct BlockBuilderWithParams {
    pub facts: Vec<Fact>,
    pub rules: Vec<Rule>,
    pub checks: Vec<Check>,
    pub parameters: HashMap<String, Expr>,
}

impl BlockBuilderWithParams {
    pub fn from_code<T: AsRef<str>>(
        source: T,
        parameters: &HashMap<String, Expr>,
    ) -> std::result::Result<Self, error::LanguageError> {
        let input = source.as_ref();
        let mut facts = vec![];
        let mut rules = vec![];
        let mut checks = vec![];
        let mut datalog_parameters = HashSet::new();
        let macro_parameters = HashSet::from_iter(parameters.keys().map(|k| k.to_string()));
        let source_result = parse_block_source(input)?;

        for (_, fact) in source_result.facts.into_iter() {
            if let Some(params) = &fact.parameters.clone() {
                for param in params.clone().keys() {
                    let p = param.clone();
                    datalog_parameters.insert(p);
                }
            }

            facts.push(fact);
        }
        for (_, rule) in source_result.rules.into_iter() {
            if let Some(params) = &rule.parameters.clone() {
                for param in params.clone().keys() {
                    let p = param.clone();
                    datalog_parameters.insert(p);
                }
            }
            rules.push(rule);
        }
        for (_, check) in source_result.checks.into_iter() {
            for query in check.queries.iter() {
                if let Some(params) = &query.parameters.clone() {
                    for param in params.clone().keys() {
                        let p = param.clone();
                        datalog_parameters.insert(p);
                    }
                }
            }
            checks.push(check);
        }

        if datalog_parameters == macro_parameters {
            Ok(BlockBuilderWithParams {
                facts,
                rules,
                checks,
                parameters: parameters.clone(),
            })
        } else {
            let unused_parameters: Vec<String> = macro_parameters
                .difference(&datalog_parameters)
                .map(|k| k.to_string())
                .collect();
            let missing_parameters: Vec<String> = datalog_parameters
                .difference(&macro_parameters)
                .map(|k| k.to_string())
                .collect();
            Err(error::LanguageError::Parameters {
                missing_parameters,
                unused_parameters,
            })
        }
    }
}

impl ToTokens for BlockBuilderWithParams {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let param_names: Vec<String> = self.parameters.clone().into_keys().collect();
        let param_values: Vec<Expr> = self.parameters.clone().into_values().collect();
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
        tokens.extend(quote! {
            let mut builder = ::biscuit_auth::builder::BlockBuilder::new();
            #(#facts_quote)*
            #(#rules_quote)*
            #(#checks_quote)*
            builder
        });
    }
}

#[derive(Clone, Debug)]
struct AuthorizerWithParams {
    pub parameters: HashMap<String, Expr>,
    pub facts: Vec<Fact>,
    pub rules: Vec<Rule>,
    pub checks: Vec<Check>,
    pub policies: Vec<Policy>,
}

impl AuthorizerWithParams {
    pub fn from_code<T: AsRef<str>>(
        source: T,
        parameters: &HashMap<String, Expr>,
    ) -> std::result::Result<Self, error::LanguageError> {
        let input = source.as_ref();
        let source_result = parse_source(input)?;
        let mut facts = Vec::new();
        let mut rules = Vec::new();
        let mut checks = Vec::new();
        let mut policies = Vec::new();

        for (_, fact) in source_result.facts.into_iter() {
            facts.push(fact);
        }
        for (_, rule) in source_result.rules.into_iter() {
            rules.push(rule);
        }
        for (_, check) in source_result.checks.into_iter() {
            checks.push(check);
        }
        for (_, policy) in source_result.policies.into_iter() {
            policies.push(policy);
        }

        Ok(AuthorizerWithParams {
            facts,
            rules,
            checks,
            policies,
            parameters: parameters.clone(),
        })
    }
}

impl ToTokens for AuthorizerWithParams {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let param_names: Vec<String> = self.parameters.clone().into_keys().collect();
        let param_values: Vec<Expr> = self.parameters.clone().into_values().collect();
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
        tokens.extend(quote! {
            let mut builder = ::biscuit_auth::Authorizer::new().unwrap();
            #(#facts_quote)*
            #(#rules_quote)*
            #(#checks_quote)*
            #(#policies_quote)*
            builder
        });
    }
}

/// create an `Authorizer` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
///
/// ```rust
/// extern crate biscuit_quote;
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
pub fn authorizer(input: TokenStream) -> TokenStream {
    let ParsedQuery {
        datalog,
        parameters,
    } = syn::parse(input).unwrap();

    let builder = AuthorizerWithParams::from_code(&datalog, &parameters).unwrap();

    let gen = quote! {
        {
          #builder
        }
    };

    gen.into()
}

struct ParsedBiscuitQuery {
    datalog: String,
    parameters: HashMap<String, Expr>,
}

impl Parse for ParsedBiscuitQuery {
    fn parse(input: ParseStream) -> Result<Self> {
        let datalog = input.parse::<LitStr>()?.value();

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

        Ok(ParsedBiscuitQuery {
            datalog,
            parameters,
        })
    }
}

/// create an `BiscuitBuilder` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
///
/// ```rust
/// extern crate biscuit_quote;
/// extern crate biscuit_auth;
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
pub fn biscuit(input: TokenStream) -> TokenStream {
    let ParsedBiscuitQuery {
        datalog,
        parameters,
    } = syn::parse(input).unwrap();

    let builder = BiscuitWithParams::from_code(&datalog, &parameters).unwrap();

    let gen = quote! {
        {
          #builder
        }
    };

    gen.into()
}

#[derive(Clone, Debug)]
struct BiscuitWithParams {
    pub parameters: HashMap<String, Expr>,
    pub facts: Vec<Fact>,
    pub rules: Vec<Rule>,
    pub checks: Vec<Check>,
}

impl BiscuitWithParams {
    pub fn from_code<T: AsRef<str>>(
        source: T,
        parameters: &HashMap<String, Expr>,
    ) -> std::result::Result<Self, error::LanguageError> {
        let input = source.as_ref();
        let source_result = parse_block_source(input)?;
        let mut facts = Vec::new();
        let mut rules = Vec::new();
        let mut checks = Vec::new();

        for (_, fact) in source_result.facts.into_iter() {
            facts.push(fact);
        }
        for (_, rule) in source_result.rules.into_iter() {
            rules.push(rule);
        }
        for (_, check) in source_result.checks.into_iter() {
            checks.push(check);
        }

        Ok(BiscuitWithParams {
            facts,
            rules,
            checks,
            parameters: parameters.clone(),
        })
    }
}

impl ToTokens for BiscuitWithParams {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let param_names: Vec<String> = self.parameters.clone().into_keys().collect();
        let param_values: Vec<Expr> = self.parameters.clone().into_values().collect();
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
        tokens.extend(quote! {
            let mut builder = ::biscuit_auth::Biscuit::builder();
            #(#facts_quote)*
            #(#rules_quote)*
            #(#checks_quote)*
            builder
        });
    }
}
