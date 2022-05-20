extern crate proc_macro;
use biscuit_auth::{
    builder::{BlockBuilder, Check, Fact, Policy, Rule},
    error,
    parser::{parse_block_source, parse_source},
};
use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use std::collections::HashMap;
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
pub fn block(input: TokenStream) -> TokenStream {
    let ParsedQuery {
        datalog,
        parameters,
    } = syn::parse(input).unwrap();

    let builder = BlockBuilderWithParams::from_code(&datalog, &parameters).unwrap();

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
    pub builder: BlockBuilder,
    pub parameters: HashMap<String, Expr>,
}

impl BlockBuilderWithParams {
    pub fn from_code<T: AsRef<str>>(
        source: T,
        parameters: &HashMap<String, Expr>,
    ) -> std::result::Result<Self, error::Token> {
        let input = source.as_ref();
        let mut builder = BlockBuilder::new();
        let source_result = parse_block_source(input)?;

        for (_, fact) in source_result.facts.into_iter() {
            builder.facts.push(fact);
        }
        for (_, rule) in source_result.rules.into_iter() {
            builder.rules.push(rule);
        }
        for (_, check) in source_result.checks.into_iter() {
            builder.checks.push(check);
        }

        Ok(BlockBuilderWithParams {
            builder,
            parameters: parameters.clone(),
        })
    }
}

impl ToTokens for BlockBuilderWithParams {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let param_names: Vec<String> = self.parameters.clone().into_keys().collect();
        let param_values: Vec<Expr> = self.parameters.clone().into_values().collect();
        let facts_quote = self.builder.facts.iter().map(|f| {
            quote! {
                let mut fact = #f;
                #(fact.set_lenient(#param_names, #param_values).unwrap();)*
                builder.add_fact(fact).unwrap();
            }
        });
        let rules_quote = self.builder.rules.iter().map(|r| {
            quote! {
                let mut rule = #r;
                #(rule.set_lenient(#param_names, #param_values).unwrap();)*
                builder.add_rule(rule).unwrap();
            }
        });
        let checks_quote = self.builder.checks.iter().map(|c| {
            quote! {
                let mut check = #c;
                #(check.set_lenient(#param_names, #param_values).unwrap();)*
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
    ) -> std::result::Result<Self, error::Token> {
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
                #(fact.set_lenient(#param_names, #param_values).unwrap();)*
                builder.add_fact(fact).unwrap();
            }
        });
        let rules_quote = self.rules.iter().map(|r| {
            quote! {
                let mut rule = #r;
                #(rule.set_lenient(#param_names, #param_values).unwrap();)*
                builder.add_rule(rule).unwrap();
            }
        });
        let checks_quote = self.checks.iter().map(|c| {
            quote! {
                let mut check = #c;
                #(check.set_lenient(#param_names, #param_values).unwrap();)*
                builder.add_check(check).unwrap();
            }
        });
        let policies_quote = self.policies.iter().map(|p| {
            quote! {
                let mut policy = #p;
                #(policy.set_lenient(#param_names, #param_values).unwrap();)*
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
