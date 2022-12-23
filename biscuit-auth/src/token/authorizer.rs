//! Authorizer structure and associated functions
use super::builder::{
    constrained_rule, date, fact, pred, rule, string, var, Binary, BlockBuilder, Check, Expression,
    Fact, Op, Policy, PolicyKind, Rule, Scope, Term,
};
use super::builder_ext::{AuthorizerExt, BuilderExt};
use super::{Biscuit, Block};
use crate::builder::{CheckKind, Convert};
use crate::crypto::PublicKey;
use crate::datalog::{self, Origin, RunLimits, SymbolTable, TrustedOrigins};
use crate::error;
use crate::time::Instant;
use crate::token;
use biscuit_parser::parser::parse_source;
use prost::Message;
use std::collections::{BTreeMap, HashSet};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    default::Default,
    fmt::Write,
    time::{Duration, SystemTime},
};

mod snapshot;
pub use snapshot::*;

/// used to check authorization policies on a token
///
/// can be created from [Biscuit::authorizer] or [Authorizer::new]
#[derive(Clone)]
pub struct Authorizer {
    authorizer_block_builder: BlockBuilder,
    world: datalog::World,
    pub(crate) symbols: datalog::SymbolTable,
    token_origins: TrustedOrigins,
    policies: Vec<Policy>,
    blocks: Option<Vec<Block>>,
    public_key_to_block_id: HashMap<usize, Vec<usize>>,
}

impl Authorizer {
    pub(crate) fn from_token(token: &Biscuit) -> Result<Self, error::Token> {
        let mut v = Authorizer::new();
        v.add_token(token)?;

        Ok(v)
    }

    /// creates a new empty authorizer
    ///
    /// this can be used to check policies when:
    /// * there is no token (unauthenticated case)
    /// * there is a lot of data to load in the authorizer on each check
    ///
    /// In the latter case, we can create an empty authorizer, load it
    /// with the facts, rules and checks, and each time a token must be checked,
    /// clone the authorizer and load the token with [`Authorizer::add_token`]
    pub fn new() -> Self {
        let world = datalog::World::new();
        let symbols = super::default_symbol_table();
        let authorizer_block_builder = BlockBuilder::new();

        Authorizer {
            authorizer_block_builder,
            world,
            symbols,
            token_origins: TrustedOrigins::default(),
            policies: vec![],
            blocks: None,
            public_key_to_block_id: HashMap::new(),
        }
    }

    /// creates an `Authorizer` from a serialized [crate::format::schema::AuthorizerPolicies]
    pub fn from(data: &[u8]) -> Result<Self, error::Token> {
        AuthorizerPolicies::deserialize(data)?.try_into()
    }

    /// add a token to an empty authorizer
    pub fn add_token(&mut self, token: &Biscuit) -> Result<(), error::Token> {
        if self.blocks.is_some() {
            return Err(error::Logic::AuthorizerNotEmpty.into());
        }

        for (key_id, block_ids) in &token.public_key_to_block_id {
            let key = token
                .symbols
                .public_keys
                .get_key(*key_id as u64)
                .ok_or(error::Format::UnknownExternalKey)?;
            let new_key_id = self.symbols.public_keys.insert(key);

            self.public_key_to_block_id
                .insert(new_key_id as usize, block_ids.clone());
        }

        let mut blocks = Vec::new();

        for i in 0..token.block_count() {
            let mut block = token.block(i)?;

            self.add_block(&mut block, i, &token.symbols)?;

            blocks.push(block);
        }

        self.blocks = Some(blocks);
        self.token_origins = TrustedOrigins::from_scopes(
            &[token::Scope::Previous],
            &TrustedOrigins::default(),
            token.block_count(),
            &self.public_key_to_block_id,
        );

        Ok(())
    }

    fn add_block(
        &mut self,
        block: &mut Block,
        i: usize,
        token_symbols: &SymbolTable,
    ) -> Result<(), error::Token> {
        // if it is a 3rd party block, it should not affect the main symbol table
        let block_symbols = if i == 0 || block.external_key.is_none() {
            &token_symbols
        } else {
            &block.symbols
        };

        let mut block_origin = Origin::default();
        block_origin.insert(i);

        let block_trusted_origins = TrustedOrigins::from_scopes(
            &block.scopes,
            &TrustedOrigins::default(),
            i,
            &self.public_key_to_block_id,
        );

        for fact in block.facts.iter() {
            let fact = Fact::convert_from(fact, block_symbols)?.convert(&mut self.symbols);
            self.world.facts.insert(&block_origin, fact);
        }

        for rule in block.rules.iter() {
            if let Err(_message) = rule.validate_variables(block_symbols) {
                return Err(
                    error::Logic::InvalidBlockRule(0, block_symbols.print_rule(rule)).into(),
                );
            }
            let rule = rule.translate(block_symbols, &mut self.symbols)?;

            let rule_trusted_origins = TrustedOrigins::from_scopes(
                &rule.scopes,
                &block_trusted_origins,
                i,
                &self.public_key_to_block_id,
            );

            self.world.rules.insert(i, &rule_trusted_origins, rule);
        }

        for check in block.checks.iter_mut() {
            let c = Check::convert_from(check, &block_symbols)?;
            *check = c.convert(&mut self.symbols);
        }

        Ok(())
    }

    /// serializes a authorizer's content
    ///
    /// you can use this to save a set of policies and load them quickly before
    /// verification. This will not store data obtained or generated from a token.
    pub fn save(&self) -> Result<AuthorizerPolicies, error::Token> {
        let facts = self
            .authorizer_block_builder
            .facts
            .iter()
            .cloned()
            .collect();

        let rules = self
            .authorizer_block_builder
            .rules
            .iter()
            .cloned()
            .collect();

        let checks = self
            .authorizer_block_builder
            .checks
            .iter()
            .cloned()
            .collect();

        Ok(AuthorizerPolicies {
            version: crate::token::MAX_SCHEMA_VERSION,
            facts,
            rules,
            checks,
            policies: self.policies.clone(),
        })
    }

    /// Add the rules, facts, checks, and policies of another `Authorizer`.
    /// If a token has already been added to `other`, it is not merged into `self`.
    pub fn merge(&mut self, mut other: Authorizer) {
        self.merge_block(other.authorizer_block_builder);
        self.policies.append(&mut other.policies);
    }

    /// Add the rules, facts, and checks of another `BlockBuilder`.
    pub fn merge_block(&mut self, other: BlockBuilder) {
        self.authorizer_block_builder.merge(other)
    }

    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token>
    where
        error::Token: From<<F as TryInto<Fact>>::Error>,
    {
        self.authorizer_block_builder.add_fact(fact)
    }

    pub fn add_rule<Ru: TryInto<Rule>>(&mut self, rule: Ru) -> Result<(), error::Token>
    where
        error::Token: From<<Ru as TryInto<Rule>>::Error>,
    {
        self.authorizer_block_builder.add_rule(rule)
    }

    pub fn add_check<C: TryInto<Check>>(&mut self, check: C) -> Result<(), error::Token>
    where
        error::Token: From<<C as TryInto<Check>>::Error>,
    {
        self.authorizer_block_builder.add_check(check)
    }

    /// adds some datalog code to the authorizer
    ///
    /// ```rust
    /// extern crate biscuit_auth as biscuit;
    ///
    /// use biscuit::Authorizer;
    ///
    /// let mut authorizer = Authorizer::new();
    ///
    /// authorizer.add_code(r#"
    ///   resource("/file1.txt");
    ///
    ///   check if user(1234);
    ///
    ///   // default allow
    ///   allow if true;
    /// "#).expect("should parse correctly");
    /// ```
    pub fn add_code<T: AsRef<str>>(&mut self, source: T) -> Result<(), error::Token> {
        self.add_code_with_params(source, HashMap::new(), HashMap::new())
    }

    pub fn add_code_with_params<T: AsRef<str>>(
        &mut self,
        source: T,
        params: HashMap<String, Term>,
        scope_params: HashMap<String, PublicKey>,
    ) -> Result<(), error::Token> {
        let source = source.as_ref();

        let source_result = parse_source(source).map_err(|e| {
            let e2: biscuit_parser::error::LanguageError = e.into();
            e2
        })?;

        for (_, fact) in source_result.facts.into_iter() {
            let mut fact: Fact = fact.into();
            for (name, value) in &params {
                let res = match fact.set(name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            fact.validate()?;
            self.authorizer_block_builder.facts.push(fact);
        }

        for (_, rule) in source_result.rules.into_iter() {
            let mut rule: Rule = rule.into();
            for (name, value) in &params {
                let res = match rule.set(name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            for (name, value) in &scope_params {
                let res = match rule.set_scope(name, *value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            rule.validate_parameters()?;
            self.authorizer_block_builder.rules.push(rule);
        }

        for (_, check) in source_result.checks.into_iter() {
            let mut check: Check = check.into();
            for (name, value) in &params {
                let res = match check.set(name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            for (name, value) in &scope_params {
                let res = match check.set_scope(name, *value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            check.validate_parameters()?;
            self.authorizer_block_builder.checks.push(check);
        }
        for (_, policy) in source_result.policies.into_iter() {
            let mut policy: Policy = policy.into();
            for (name, value) in &params {
                let res = match policy.set(name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            for (name, value) in &scope_params {
                let res = match policy.set_scope(name, *value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            policy.validate_parameters()?;
            self.policies.push(policy);
        }

        Ok(())
    }

    pub fn add_scope(&mut self, scope: Scope) {
        self.authorizer_block_builder.add_scope(scope);
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// ```rust
    /// # use biscuit_auth::KeyPair;
    /// # use biscuit_auth::Biscuit;
    /// let keypair = KeyPair::new();
    /// let mut builder = Biscuit::builder();
    /// builder.add_fact("user(\"John Doe\", 42)");
    ///
    /// let biscuit = builder.build(&keypair).unwrap();
    ///
    /// let mut authorizer = biscuit.authorizer().unwrap();
    /// let res: Vec<(String, i64)> = authorizer.query("data($name, $id) <- user($name, $id)").unwrap();
    /// # assert_eq!(res.len(), 1);
    /// # assert_eq!(res[0].0, "John Doe");
    /// # assert_eq!(res[0].1, 42);
    /// ```
    // TODO rename as `query_token`
    pub fn query<R: TryInto<Rule>, T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: R,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        self.query_with_limits(rule, AuthorizerLimits::default())
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// this only sees facts from the authorizer and the authority block
    ///
    /// this method can specify custom runtime limits
    pub fn query_with_limits<R: TryInto<Rule>, T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: R,
        limits: AuthorizerLimits,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let rule = rule.try_into()?.convert(&mut self.symbols);

        let rule_trusted_origins = TrustedOrigins::from_scopes(
            &rule.scopes,
            &TrustedOrigins::default(), // for queries, we don't want to default on the authorizer trust
            // queries are there to explore the final state of the world,
            // whereas authorizer contents are there to authorize or not
            // a token
            usize::MAX,
            &self.public_key_to_block_id,
        );

        self.world
            .run_with_limits(&self.symbols, limits.into())
            .map_err(error::Token::RunLimit)?;
        let res = self
            .world
            .query_rule(rule, usize::MAX, &rule_trusted_origins, &self.symbols);

        res //.drain(..)
            .inner
            .into_iter()
            .flat_map(|(_, set)| set.into_iter())
            .map(|f| Fact::convert_from(&f, &self.symbols))
            .map(|fact| {
                fact.map_err(error::Token::Format)
                    .and_then(|f| f.try_into().map_err(Into::into))
            })
            .collect()
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// this has access to the facts generated when evaluating all the blocks
    ///
    /// ```rust
    /// # use biscuit_auth::KeyPair;
    /// # use biscuit_auth::Biscuit;
    /// let keypair = KeyPair::new();
    /// let mut builder = Biscuit::builder();
    /// builder.add_fact("user(\"John Doe\", 42)");
    ///
    /// let biscuit = builder.build(&keypair).unwrap();
    ///
    /// let mut authorizer = biscuit.authorizer().unwrap();
    /// let res: Vec<(String, i64)> = authorizer.query("data($name, $id) <- user($name, $id)").unwrap();
    /// # assert_eq!(res.len(), 1);
    /// # assert_eq!(res[0].0, "John Doe");
    /// # assert_eq!(res[0].1, 42);
    /// ```
    pub fn query_all<R: TryInto<Rule>, T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: R,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        self.query_all_with_limits(rule, AuthorizerLimits::default())
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// this has access to the facts generated when evaluating all the blocks
    ///
    /// this method can specify custom runtime limits
    pub fn query_all_with_limits<
        R: TryInto<Rule>,
        T: TryFrom<Fact, Error = E>,
        E: Into<error::Token>,
    >(
        &mut self,
        rule: R,
        limits: AuthorizerLimits,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let rule = rule.try_into()?.convert(&mut self.symbols);

        self.world
            .run_with_limits(&self.symbols, limits.into())
            .map_err(error::Token::RunLimit)?;

        let rule_trusted_origins = if rule.scopes.is_empty() {
            self.token_origins.clone()
        } else {
            TrustedOrigins::from_scopes(
                &rule.scopes,
                &TrustedOrigins::default(), // for queries, we don't want to default on the authorizer trust
                // queries are there to explore the final state of the world,
                // whereas authorizer contents are there to authorize or not
                // a token
                usize::MAX,
                &self.public_key_to_block_id,
            )
        };

        let res = self
            .world
            .query_rule(rule, 0, &rule_trusted_origins, &self.symbols);

        let r: HashSet<_> = res.into_iter().map(|(_, fact)| fact).collect();

        r.into_iter()
            .map(|f| Fact::convert_from(&f, &self.symbols))
            .map(|fact| {
                fact.map_err(error::Token::Format)
                    .and_then(|f| f.try_into().map_err(Into::into))
            })
            .collect::<Result<Vec<T>, _>>()
    }

    /// adds a fact with the current time
    pub fn set_time(&mut self) {
        let fact = fact("time", &[date(&SystemTime::now())]);
        self.authorizer_block_builder.add_fact(fact).unwrap();
    }

    /// add a policy to the authorizer
    pub fn add_policy<P: TryInto<Policy>>(&mut self, policy: P) -> Result<(), error::Token>
    where
        error::Token: From<<P as TryInto<Policy>>::Error>,
    {
        let policy = policy.try_into()?;
        policy.validate_parameters()?;
        self.policies.push(policy);
        Ok(())
    }

    /// todo remove, it's covered in BuilderExt
    /// adds a `allow if true` policy
    pub fn allow(&mut self) -> Result<(), error::Token> {
        self.add_policy("allow if true")
    }

    /// adds a `deny if true` policy
    pub fn deny(&mut self) -> Result<(), error::Token> {
        self.add_policy("deny if true")
    }

    /// verifies the checks and policiies
    ///
    /// on error, this can return a list of all the failed checks or deny policy
    /// on success, it returns the index of the policy that matched
    pub fn authorize(&mut self) -> Result<usize, error::Token> {
        self.authorize_with_limits(AuthorizerLimits::default())
    }

    /// verifies the checks and policiies
    ///
    /// on error, this can return a list of all the failed checks or deny policy
    ///
    /// this method can specify custom runtime limits
    /// todo consume the input to prevent further direct use
    pub fn authorize_with_limits(
        &mut self,
        limits: AuthorizerLimits,
    ) -> Result<usize, error::Token> {
        let start = Instant::now();
        let time_limit = start + limits.max_time;
        let mut errors = vec![];
        let mut policy_result: Option<Result<usize, usize>> = None;

        let mut authorizer_origin = Origin::default();
        authorizer_origin.insert(usize::MAX);

        let authorizer_scopes: Vec<token::Scope> = self
            .authorizer_block_builder
            .scopes
            .clone()
            .iter()
            .map(|s| s.convert(&mut self.symbols))
            .collect();

        let authorizer_trusted_origins = TrustedOrigins::from_scopes(
            &authorizer_scopes,
            &TrustedOrigins::default(),
            usize::MAX,
            &self.public_key_to_block_id,
        );

        for fact in &self.authorizer_block_builder.facts {
            self.world
                .facts
                .insert(&authorizer_origin, fact.convert(&mut self.symbols));
        }

        for rule in &self.authorizer_block_builder.rules {
            let rule = rule.convert(&mut self.symbols);

            let rule_trusted_origins = TrustedOrigins::from_scopes(
                &rule.scopes,
                &authorizer_trusted_origins,
                usize::MAX,
                &self.public_key_to_block_id,
            );

            self.world
                .rules
                .insert(usize::MAX, &rule_trusted_origins, rule);
        }

        self.world
            .run_with_limits(&self.symbols, RunLimits::default())
            .map_err(error::Token::RunLimit)?;
        //self.world.rules.clear();

        let authorizer_scopes: Vec<token::Scope> = self
            .authorizer_block_builder
            .scopes
            .clone()
            .iter()
            .map(|s| s.convert(&mut self.symbols))
            .collect();

        let authorizer_trusted_origins = TrustedOrigins::from_scopes(
            &authorizer_scopes,
            &TrustedOrigins::default(),
            usize::MAX,
            &self.public_key_to_block_id,
        );

        for (i, check) in self.authorizer_block_builder.checks.iter().enumerate() {
            let c = check.convert(&mut self.symbols);
            let mut successful = false;

            for query in check.queries.iter() {
                let query = query.convert(&mut self.symbols);
                let rule_trusted_origins = TrustedOrigins::from_scopes(
                    &query.scopes,
                    &authorizer_trusted_origins,
                    usize::MAX,
                    &self.public_key_to_block_id,
                );
                let res = match check.kind {
                    CheckKind::One => self.world.query_match(
                        query,
                        usize::MAX,
                        &rule_trusted_origins,
                        &self.symbols,
                    ),
                    CheckKind::All => {
                        self.world
                            .query_match_all(query, &rule_trusted_origins, &self.symbols)
                    }
                };

                let now = Instant::now();
                if now >= time_limit {
                    return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                }

                if res {
                    successful = true;
                    break;
                }
            }

            if !successful {
                errors.push(error::FailedCheck::Authorizer(
                    error::FailedAuthorizerCheck {
                        check_id: i as u32,
                        rule: self.symbols.print_check(&c),
                    },
                ));
            }
        }

        if let Some(blocks) = self.blocks.as_ref() {
            for (j, check) in blocks[0].checks.iter().enumerate() {
                let mut successful = false;

                let authority_trusted_origins = TrustedOrigins::from_scopes(
                    &blocks[0].scopes,
                    &TrustedOrigins::default(),
                    0,
                    &self.public_key_to_block_id,
                );

                for query in check.queries.iter() {
                    let rule_trusted_origins = TrustedOrigins::from_scopes(
                        &query.scopes,
                        &authority_trusted_origins,
                        0,
                        &self.public_key_to_block_id,
                    );
                    let res = match check.kind {
                        CheckKind::One => self.world.query_match(
                            query.clone(),
                            0,
                            &rule_trusted_origins,
                            &self.symbols,
                        ),
                        CheckKind::All => self.world.query_match_all(
                            query.clone(),
                            &rule_trusted_origins,
                            &self.symbols,
                        ),
                    };

                    let now = Instant::now();
                    if now >= time_limit {
                        return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                    }

                    if res {
                        successful = true;
                        break;
                    }
                }

                if !successful {
                    errors.push(error::FailedCheck::Block(error::FailedBlockCheck {
                        block_id: 0u32,
                        check_id: j as u32,
                        rule: self.symbols.print_check(&check),
                    }));
                }
            }
        }

        'policies_test: for (i, policy) in self.policies.iter().enumerate() {
            for query in policy.queries.iter() {
                let query = query.convert(&mut self.symbols);
                let rule_trusted_origins = TrustedOrigins::from_scopes(
                    &query.scopes,
                    &authorizer_trusted_origins,
                    usize::MAX,
                    &self.public_key_to_block_id,
                );

                let res =
                    self.world
                        .query_match(query, usize::MAX, &rule_trusted_origins, &self.symbols);

                let now = Instant::now();
                if now >= time_limit {
                    return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                }

                if res {
                    match policy.kind {
                        PolicyKind::Allow => policy_result = Some(Ok(i)),
                        PolicyKind::Deny => policy_result = Some(Err(i)),
                    };
                    break 'policies_test;
                }
            }
        }

        if let Some(blocks) = self.blocks.as_ref() {
            for (i, block) in (&blocks[1..]).iter().enumerate() {
                let block_trusted_origins = TrustedOrigins::from_scopes(
                    &block.scopes,
                    &TrustedOrigins::default(),
                    i + 1,
                    &self.public_key_to_block_id,
                );

                self.world
                    .run_with_limits(&self.symbols, RunLimits::default())
                    .map_err(error::Token::RunLimit)?;

                for (j, check) in block.checks.iter().enumerate() {
                    let mut successful = false;

                    for query in check.queries.iter() {
                        let rule_trusted_origins = TrustedOrigins::from_scopes(
                            &query.scopes,
                            &block_trusted_origins,
                            i + 1,
                            &self.public_key_to_block_id,
                        );

                        let res = match check.kind {
                            CheckKind::One => self.world.query_match(
                                query.clone(),
                                i + 1,
                                &rule_trusted_origins,
                                &self.symbols,
                            ),
                            CheckKind::All => self.world.query_match_all(
                                query.clone(),
                                &rule_trusted_origins,
                                &self.symbols,
                            ),
                        };

                        let now = Instant::now();
                        if now >= time_limit {
                            return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                        }

                        if res {
                            successful = true;
                            break;
                        }
                    }

                    if !successful {
                        errors.push(error::FailedCheck::Block(error::FailedBlockCheck {
                            block_id: (i + 1) as u32,
                            check_id: j as u32,
                            rule: self.symbols.print_check(&check),
                        }));
                    }
                }
            }
        }

        match (policy_result, errors.is_empty()) {
            (Some(Ok(i)), true) => Ok(i),
            (None, _) => Err(error::Token::FailedLogic(error::Logic::NoMatchingPolicy {
                checks: errors,
            })),
            (Some(Ok(i)), _) => Err(error::Token::FailedLogic(error::Logic::Unauthorized {
                policy: error::MatchedPolicy::Allow(i),
                checks: errors,
            })),
            (Some(Err(i)), _) => Err(error::Token::FailedLogic(error::Logic::Unauthorized {
                policy: error::MatchedPolicy::Deny(i),
                checks: errors,
            })),
        }
    }

    /// prints the content of the authorizer
    pub fn print_world(&self) -> String {
        let facts: BTreeMap<_, _> = self
            .world
            .facts
            .inner
            .iter()
            .map(|(origin, facts)| {
                (
                    origin,
                    facts
                        .iter()
                        .map(|f| self.symbols.print_fact(f))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        let rules: BTreeMap<_, _> = self
            .world
            .rules
            .inner
            .iter()
            .map(|(origin, rules)| {
                (
                    origin,
                    rules
                        .iter()
                        .map(|(_, r)| self.symbols.print_rule(r))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        let mut checks = Vec::new();
        for (index, check) in self.authorizer_block_builder.checks.iter().enumerate() {
            checks.push(format!("Authorizer[{}]: {}", index, check));
        }

        if let Some(blocks) = &self.blocks {
            for (i, block) in blocks.iter().enumerate() {
                for (j, check) in block.checks.iter().enumerate() {
                    checks.push(format!(
                        "Block[{}][{}]: {}",
                        i,
                        j,
                        self.symbols.print_check(check)
                    ));
                }
            }
        }

        let mut policies = Vec::new();
        for policy in self.policies.iter() {
            policies.push(policy.to_string());
        }

        format!(
            "World {{\n  facts: {:#?}\n  rules: {:#?}\n  checks: {:#?}\n  policies: {:#?}\n}}",
            facts, rules, checks, policies
        )
    }

    /// returns all of the data loaded in the authorizer
    pub fn dump(&self) -> (Vec<Fact>, Vec<Rule>, Vec<Check>, Vec<Policy>) {
        let mut checks = self.authorizer_block_builder.checks.clone();
        if let Some(blocks) = &self.blocks {
            for block in blocks {
                checks.extend(
                    block
                        .checks
                        .iter()
                        .map(|c| Check::convert_from(c, &self.symbols).unwrap()),
                );
            }
        }

        let mut facts = self
            .world
            .facts
            .iter_all()
            .map(|f| Fact::convert_from(f.1, &self.symbols))
            .collect::<Result<Vec<_>, error::Format>>()
            .unwrap();
        facts.extend(self.authorizer_block_builder.facts.clone());

        let mut rules = self
            .world
            .rules
            .iter_all()
            .map(|r| Rule::convert_from(r.1, &self.symbols))
            .collect::<Result<Vec<_>, error::Format>>()
            .unwrap();
        rules.extend(self.authorizer_block_builder.rules.clone());

        (facts, rules, checks, self.policies.clone())
    }

    pub fn dump_code(&self) -> String {
        let (facts, rules, checks, policies) = self.dump();
        let mut f = String::new();
        for fact in &facts {
            let _ = writeln!(f, "{fact};");
        }
        if !facts.is_empty() {
            let _ = writeln!(f, "");
        }

        for rule in &rules {
            let _ = writeln!(f, "{rule};");
        }
        if !rules.is_empty() {
            let _ = writeln!(f, "");
        }

        for check in &checks {
            let _ = writeln!(f, "{check};");
        }
        if !checks.is_empty() {
            let _ = writeln!(f, "");
        }

        for policy in &policies {
            let _ = writeln!(f, "{policy};");
        }
        f
    }
}

impl TryFrom<AuthorizerPolicies> for Authorizer {
    type Error = error::Token;

    fn try_from(authorizer_policies: AuthorizerPolicies) -> Result<Self, Self::Error> {
        let AuthorizerPolicies {
            version: _,
            facts,
            rules,
            checks,
            policies,
        } = authorizer_policies;

        let mut authorizer = Self::new();

        for fact in facts.into_iter() {
            authorizer.authorizer_block_builder.add_fact(fact)?;
        }

        for rule in rules.into_iter() {
            authorizer.authorizer_block_builder.add_rule(rule)?;
        }

        for check in checks.into_iter() {
            authorizer.authorizer_block_builder.add_check(check)?;
        }

        for policy in policies {
            authorizer.policies.push(policy);
        }

        Ok(authorizer)
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizerPolicies {
    pub version: u32,
    /// list of facts provided by this block
    pub facts: Vec<Fact>,
    /// list of rules provided by blocks
    pub rules: Vec<Rule>,
    /// checks that the token and ambient data must validate
    pub checks: Vec<Check>,
    pub policies: Vec<Policy>,
}

impl AuthorizerPolicies {
    pub fn serialize(&self) -> Result<Vec<u8>, error::Token> {
        let proto = crate::format::convert::authorizer_to_proto_authorizer(self);

        let mut v = Vec::new();

        proto
            .encode(&mut v)
            .map(|_| v)
            .map_err(|e| error::Format::SerializationError(format!("serialization error: {:?}", e)))
            .map_err(error::Token::Format)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, error::Token> {
        let data = crate::format::schema::AuthorizerPolicies::decode(data).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        Ok(crate::format::convert::proto_authorizer_to_authorizer(
            &data,
        )?)
    }
}

/// runtime limits for the Datalog engine
#[derive(Debug, Clone)]
pub struct AuthorizerLimits {
    /// maximum number of Datalog facts (memory usage)
    pub max_facts: u32,
    /// maximum number of iterations of the rules applications (prevents degenerate rules)
    pub max_iterations: u32,
    /// maximum execution time
    pub max_time: Duration,
}

impl Default for AuthorizerLimits {
    fn default() -> Self {
        AuthorizerLimits {
            max_facts: 1000,
            max_iterations: 100,
            max_time: Duration::from_millis(1),
        }
    }
}

impl std::convert::From<AuthorizerLimits> for crate::datalog::RunLimits {
    fn from(limits: AuthorizerLimits) -> Self {
        crate::datalog::RunLimits {
            max_facts: limits.max_facts,
            max_iterations: limits.max_iterations,
            max_time: limits.max_time,
        }
    }
}

impl BuilderExt for Authorizer {
    fn add_resource(&mut self, name: &str) {
        let f = fact("resource", &[string(name)]);
        self.add_fact(f).unwrap();
    }
    fn check_resource(&mut self, name: &str) {
        self.add_check(Check {
            queries: vec![rule(
                "resource_check",
                &[string("resource_check")],
                &[pred("resource", &[string(name)])],
            )],
            kind: CheckKind::One,
        })
        .unwrap();
    }
    fn add_operation(&mut self, name: &str) {
        let f = fact("operation", &[string(name)]);
        self.add_fact(f).unwrap();
    }
    fn check_operation(&mut self, name: &str) {
        self.add_check(Check {
            queries: vec![rule(
                "operation_check",
                &[string("operation_check")],
                &[pred("operation", &[string(name)])],
            )],
            kind: CheckKind::One,
        })
        .unwrap();
    }
    fn check_resource_prefix(&mut self, prefix: &str) {
        let check = constrained_rule(
            "prefix",
            &[var("resource")],
            &[pred("resource", &[var("resource")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("resource")),
                    Op::Value(string(prefix)),
                    Op::Binary(Binary::Prefix),
                ],
            }],
        );

        self.add_check(Check {
            queries: vec![check],
            kind: CheckKind::One,
        })
        .unwrap();
    }

    fn check_resource_suffix(&mut self, suffix: &str) {
        let check = constrained_rule(
            "suffix",
            &[var("resource")],
            &[pred("resource", &[var("resource")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("resource")),
                    Op::Value(string(suffix)),
                    Op::Binary(Binary::Suffix),
                ],
            }],
        );

        self.add_check(Check {
            queries: vec![check],
            kind: CheckKind::One,
        })
        .unwrap();
    }

    fn check_expiration_date(&mut self, exp: SystemTime) {
        let check = constrained_rule(
            "expiration",
            &[var("time")],
            &[pred("time", &[var("time")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("time")),
                    Op::Value(date(&exp)),
                    Op::Binary(Binary::LessOrEqual),
                ],
            }],
        );

        self.add_check(Check {
            queries: vec![check],
            kind: CheckKind::One,
        })
        .unwrap();
    }
}

impl AuthorizerExt for Authorizer {
    fn add_allow_all(&mut self) {
        self.add_policy("allow if true").unwrap();
    }
    fn add_deny_all(&mut self) {
        self.add_policy("deny if true").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::{builder::BlockBuilder, KeyPair};

    use super::*;

    #[test]
    fn empty_authorizer() {
        let mut authorizer = Authorizer::new();
        authorizer.add_policy("allow if true").unwrap();
        assert_eq!(authorizer.authorize(), Ok(0));
    }

    #[test]
    fn parameter_substitution() {
        let mut authorizer = Authorizer::new();
        let mut params = HashMap::new();
        params.insert("p1".to_string(), "value".into());
        params.insert("p2".to_string(), 0i64.into());
        params.insert("p3".to_string(), true.into());
        let mut scope_params = HashMap::new();
        scope_params.insert(
            "pk".to_string(),
            PublicKey::from_bytes(
                &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db")
                    .unwrap(),
            )
            .unwrap(),
        );
        authorizer
            .add_code_with_params(
                r#"
                  fact({p1}, "value");
                  rule($var, {p2}) <- fact($var, {p2});
                  check if {p3};
                  allow if {p3} trusting {pk};
              "#,
                params,
                scope_params,
            )
            .unwrap();
    }

    #[test]
    fn forbid_unbound_parameters() {
        let mut builder = Authorizer::new();

        let mut fact = Fact::try_from("fact({p1}, {p4})").unwrap();
        fact.set("p1", "hello").unwrap();
        let res = builder.add_fact(fact);
        assert_eq!(
            res,
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec!["p4".to_string()],
                    unused_parameters: vec![],
                }
            ))
        );
        let mut rule = Rule::try_from(
            "fact($var1, {p2}) <- f1($var1, $var3), f2({p2}, $var3, {p4}), $var3.starts_with({p2})",
        )
        .unwrap();
        rule.set("p2", "hello").unwrap();
        let res = builder.add_rule(rule);
        assert_eq!(
            res,
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec!["p4".to_string()],
                    unused_parameters: vec![],
                }
            ))
        );
        let mut check = Check::try_from("check if {p4}, {p3}").unwrap();
        check.set("p3", true).unwrap();
        let res = builder.add_check(check);
        assert_eq!(
            res,
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec!["p4".to_string()],
                    unused_parameters: vec![],
                }
            ))
        );
        let mut policy = Policy::try_from("allow if {p4}, {p3}").unwrap();
        policy.set("p3", true).unwrap();

        let res = builder.add_policy(policy);
        assert_eq!(
            res,
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec!["p4".to_string()],
                    unused_parameters: vec![],
                }
            ))
        );
    }

    #[test]
    fn forbid_unbound_parameters_in_add_code() {
        let mut builder = Authorizer::new();
        let mut params = HashMap::new();
        params.insert("p1".to_string(), "hello".into());
        params.insert("p2".to_string(), 1i64.into());
        params.insert("p4".to_string(), "this will be ignored".into());
        let res = builder.add_code_with_params(
            r#"fact({p1}, "value");
             rule($head_var) <- f1($head_var), {p2} > 0;
             check if {p3};
             allow if {p3};
            "#,
            params,
            HashMap::new(),
        );

        assert_eq!(
            res,
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec!["p3".to_string()],
                    unused_parameters: vec![],
                }
            ))
        )
    }

    #[test]
    fn query_authorizer_from_token_tuple() {
        use crate::Biscuit;
        use crate::KeyPair;
        let keypair = KeyPair::new();
        let mut builder = Biscuit::builder();
        builder.add_fact("user(\"John Doe\", 42)").unwrap();

        let biscuit = builder.build(&keypair).unwrap();

        let mut authorizer = biscuit.authorizer().unwrap();
        let res: Vec<(String, i64)> = authorizer
            .query("data($name, $id) <- user($name, $id)")
            .unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].0, "John Doe");
        assert_eq!(res[0].1, 42);
    }

    #[test]
    fn query_authorizer_from_token_string() {
        use crate::Biscuit;
        use crate::KeyPair;
        let keypair = KeyPair::new();
        let mut builder = Biscuit::builder();
        builder.add_fact("user(\"John Doe\")").unwrap();

        let biscuit = builder.build(&keypair).unwrap();

        let mut authorizer = biscuit.authorizer().unwrap();
        let res: Vec<(String,)> = authorizer.query("data($name) <- user($name)").unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].0, "John Doe");
    }

    #[test]
    fn authorizer_with_scopes() {
        let root = KeyPair::new();
        let external = KeyPair::new();

        let mut builder = Biscuit::builder();
        let mut scope_params = HashMap::new();
        scope_params.insert("external_pub".to_string(), external.public());
        builder
            .add_code_with_params(
                r#"right("read");
               check if group("admin") trusting {external_pub};
            "#,
                HashMap::new(),
                scope_params,
            )
            .unwrap();

        let biscuit1 = builder.build(&root).unwrap();

        let req = biscuit1.third_party_request().unwrap();

        let mut builder = BlockBuilder::new();
        builder
            .add_code(
                r#"group("admin");
             check if right("read");
            "#,
            )
            .unwrap();
        let res = req.create_block(&external.private(), builder).unwrap();
        let biscuit2 = biscuit1.append_third_party(external.public(), res).unwrap();

        let mut authorizer = Authorizer::new();
        let external2 = KeyPair::new();

        let mut scope_params = HashMap::new();
        scope_params.insert("external".to_string(), external.public());
        scope_params.insert("external2".to_string(), external2.public());

        authorizer
            .add_code_with_params(
                r#"
            // this rule trusts both the third-party block and the authority, and can access facts
            // from both
            possible(true) <- right($right), group("admin") trusting authority, {external};

            // this rule only trusts the third-party block and can't access authority facts
            // it should _not_ generate a fact
            impossible(true) <- right("read") trusting {external2};

            authorizer(true);

            check if possible(true) trusting authority, {external};
            deny if impossible(true) trusting {external2};
            allow if true;
            "#,
                HashMap::new(),
                scope_params,
            )
            .unwrap();

        authorizer.add_token(&biscuit2).unwrap();

        println!("token:\n{}", biscuit2);
        println!("world:\n{}", authorizer.print_world());

        let res = authorizer.authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_millis(5), //Set 5 milliseconds as the maximum time allowed for the authorization due to "cheap" worker on GitHub Actions
            ..Default::default()
        });
        println!("world after:\n{}", authorizer.print_world());

        res.unwrap();

        // authorizer facts are always visible, no matter what
        let authorizer_facts: Vec<Fact> = authorizer
            .query("authorizer(true) <- authorizer(true)")
            .unwrap();

        assert_eq!(authorizer_facts.len(), 1);

        // authority facts are visible by default
        let authority_facts: Vec<Fact> =
            authorizer.query("right($right) <- right($right)").unwrap();
        assert_eq!(authority_facts.len(), 1);

        // authority facts are not visible if
        // there is an explicit rule scope annotation that does
        // not cover previous or authority
        let authority_facts_untrusted: Vec<Fact> = authorizer
            .query({
                let mut r: Rule = "right($right) <- right($right) trusting {external}"
                    .try_into()
                    .unwrap();
                r.set_scope("external", external.public()).unwrap();
                r
            })
            .unwrap();
        assert_eq!(authority_facts_untrusted.len(), 0);

        // block facts are not visible by default
        let block_facts_untrusted: Vec<Fact> =
            authorizer.query("group($group) <- group($group)").unwrap();
        assert_eq!(block_facts_untrusted.len(), 0);

        // block facts are visible if trusted
        let block_facts_trusted: Vec<Fact> = authorizer
            .query({
                let mut r: Rule = "group($group) <- group($group) trusting {external}"
                    .try_into()
                    .unwrap();
                r.set_scope("external", external.public()).unwrap();
                r
            })
            .unwrap();
        assert_eq!(block_facts_trusted.len(), 1);

        // block facts are visible by default with query_all
        let block_facts_query_all: Vec<Fact> = authorizer
            .query_all("group($group) <- group($group)")
            .unwrap();
        assert_eq!(block_facts_query_all.len(), 1);

        // block facts are not visible with query_all if the query has an explicit
        // scope annotation that does not trust them
        let block_facts_query_all_explicit: Vec<Fact> = authorizer
            .query_all("group($group) <- group($group) trusting authority")
            .unwrap();
        assert_eq!(block_facts_query_all_explicit.len(), 0);
    }
}
