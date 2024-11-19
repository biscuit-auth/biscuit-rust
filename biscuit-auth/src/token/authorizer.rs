//! Authorizer structure and associated functions
use super::builder::{
    constrained_rule, date, fact, pred, rule, string, var, Binary, BlockBuilder, Check, Expression,
    Fact, Op, Policy, PolicyKind, Rule, Scope, Term,
};
use super::builder_ext::{AuthorizerExt, BuilderExt};
use super::{Biscuit, Block};
use crate::builder::{self, CheckKind, Convert};
use crate::crypto::PublicKey;
use crate::datalog::{self, Origin, RunLimits, SymbolTable, TrustedOrigins};
use crate::error;
use crate::time::Instant;
use crate::token;
use biscuit_parser::parser::parse_source;
use prost::Message;
use std::collections::{BTreeMap, HashSet};
use std::time::Duration;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    default::Default,
    fmt::Write,
    time::SystemTime,
};

mod snapshot;

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
    limits: AuthorizerLimits,
    execution_time: Duration,
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
            limits: AuthorizerLimits::default(),
            execution_time: Duration::default(),
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

        for (i, block) in token.container.blocks.iter().enumerate() {
            if let Some(sig) = block.external_signature.as_ref() {
                let new_key_id = self.symbols.public_keys.insert(&sig.public_key);

                self.public_key_to_block_id
                    .entry(new_key_id as usize)
                    .or_default()
                    .push(i + 1);
            }
        }

        let mut blocks = Vec::new();

        for i in 0..token.block_count() {
            let mut block = token.block(i)?;

            self.load_and_translate_block(&mut block, i, &token.symbols)?;

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

    /// we need to modify the block loaded from the token, because the authorizer's and the token's symbol table can differ
    fn load_and_translate_block(
        &mut self,
        block: &mut Block,
        i: usize,
        token_symbols: &SymbolTable,
    ) -> Result<(), error::Token> {
        // if it is a 3rd party block, it should not affect the main symbol table
        let block_symbols = if i == 0 || block.external_key.is_none() {
            token_symbols.clone()
        } else {
            block.symbols.clone()
        };

        let mut block_origin = Origin::default();
        block_origin.insert(i);

        for scope in block.scopes.iter_mut() {
            *scope = builder::Scope::convert_from(scope, &block_symbols)
                .map(|s| s.convert(&mut self.symbols))?;
        }

        let block_trusted_origins = TrustedOrigins::from_scopes(
            &block.scopes,
            &TrustedOrigins::default(),
            i,
            &self.public_key_to_block_id,
        );

        for fact in block.facts.iter_mut() {
            *fact = Fact::convert_from(fact, &block_symbols)?.convert(&mut self.symbols);
            self.world.facts.insert(&block_origin, fact.clone());
        }

        for rule in block.rules.iter_mut() {
            if let Err(_message) = rule.validate_variables(&block_symbols) {
                return Err(
                    error::Logic::InvalidBlockRule(0, block_symbols.print_rule(rule)).into(),
                );
            }
            *rule = rule.translate(&block_symbols, &mut self.symbols)?;

            let rule_trusted_origins = TrustedOrigins::from_scopes(
                &rule.scopes,
                &block_trusted_origins,
                i,
                &self.public_key_to_block_id,
            );

            self.world
                .rules
                .insert(i, &rule_trusted_origins, rule.clone());
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
        let facts = self.authorizer_block_builder.facts.to_vec();

        let rules = self.authorizer_block_builder.rules.to_vec();

        let checks = self.authorizer_block_builder.checks.to_vec();

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

    /// Returns the runtime limits of the authorizer
    ///
    /// Those limits cover all the executions under the `authorize`, `query` and `query_all` methods
    pub fn limits(&self) -> &AuthorizerLimits {
        &self.limits
    }

    /// Sets the runtime limits of the authorizer
    ///
    /// Those limits cover all the executions under the `authorize`, `query` and `query_all` methods
    pub fn set_limits(&mut self, limits: AuthorizerLimits) {
        self.limits = limits;
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// ```rust
    /// # use biscuit_auth::KeyPair;
    /// # use biscuit_auth::Biscuit;
    /// # use biscuit_auth::builder::Algorithm;
    /// let keypair = KeyPair::new(Algorithm::Ed25519);
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
        let mut limits = self.limits.clone();
        limits.max_iterations -= self.world.iterations;
        if self.execution_time >= limits.max_time {
            return Err(error::Token::RunLimit(error::RunLimit::Timeout));
        }
        limits.max_time -= self.execution_time;

        self.query_with_limits(rule, limits)
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// this only sees facts from the authorizer and the authority block
    ///
    /// this method overrides the authorizer's runtime limits, just for this calls
    pub fn query_with_limits<R: TryInto<Rule>, T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: R,
        limits: AuthorizerLimits,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let rule = rule.try_into()?.convert(&mut self.symbols);

        let start = Instant::now();
        let result = self.query_inner(rule, limits);
        self.execution_time += start.elapsed();

        result
    }

    fn query_inner<T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: datalog::Rule,
        limits: AuthorizerLimits,
    ) -> Result<Vec<T>, error::Token> {
        let rule_trusted_origins = TrustedOrigins::from_scopes(
            &rule.scopes,
            &TrustedOrigins::default(), // for queries, we don't want to default on the authorizer trust
            // queries are there to explore the final state of the world,
            // whereas authorizer contents are there to authorize or not
            // a token
            usize::MAX,
            &self.public_key_to_block_id,
        );

        self.world.run_with_limits(&self.symbols, limits)?;
        let res = self
            .world
            .query_rule(rule, usize::MAX, &rule_trusted_origins, &self.symbols)?;

        res.inner
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
    /// # use biscuit_auth::builder::Algorithm;
    /// let keypair = KeyPair::new(Algorithm::Ed25519,);
    /// let mut builder = Biscuit::builder();
    /// builder.add_fact("user(\"John Doe\", 42)");
    ///
    /// let biscuit = builder.build(&keypair).unwrap();
    ///
    /// let mut authorizer = biscuit.authorizer().unwrap();
    /// let res: Vec<(String, i64)> = authorizer.query_all("data($name, $id) <- user($name, $id)").unwrap();
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
        let mut limits = self.limits.clone();
        limits.max_iterations -= self.world.iterations;
        if self.execution_time >= limits.max_time {
            return Err(error::Token::RunLimit(error::RunLimit::Timeout));
        }
        limits.max_time -= self.execution_time;

        self.query_all_with_limits(rule, limits)
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// this has access to the facts generated when evaluating all the blocks
    ///
    /// this method overrides the authorizer's runtime limits, just for this calls
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

        let start = Instant::now();
        let result = self.query_all_inner(rule, limits);
        self.execution_time += start.elapsed();

        result
    }

    fn query_all_inner<T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: datalog::Rule,
        limits: AuthorizerLimits,
    ) -> Result<Vec<T>, error::Token> {
        self.world.run_with_limits(&self.symbols, limits)?;

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
            .query_rule(rule, 0, &rule_trusted_origins, &self.symbols)?;

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

    /// returns the elapsed execution time
    pub fn execution_time(&self) -> Duration {
        self.execution_time
    }

    /// returns the number of fact generation iterations
    pub fn iterations(&self) -> u64 {
        self.world.iterations
    }

    /// returns the number of facts
    pub fn fact_count(&self) -> usize {
        self.world.facts.len()
    }

    /// verifies the checks and policies
    ///
    /// on error, this can return a list of all the failed checks or deny policy
    /// on success, it returns the index of the policy that matched
    pub fn authorize(&mut self) -> Result<usize, error::Token> {
        let mut limits = self.limits.clone();
        limits.max_iterations -= self.world.iterations;
        if self.execution_time >= limits.max_time {
            return Err(error::Token::RunLimit(error::RunLimit::Timeout));
        }
        limits.max_time -= self.execution_time;

        self.authorize_with_limits(limits)
    }

    /// TODO: consume the input to prevent further direct use
    /// verifies the checks and policies
    ///
    /// on error, this can return a list of all the failed checks or deny policy
    ///
    /// this method overrides the authorizer's runtime limits, just for this calls
    pub fn authorize_with_limits(
        &mut self,
        limits: AuthorizerLimits,
    ) -> Result<usize, error::Token> {
        let start = Instant::now();
        let result = self.authorize_inner(limits);
        self.execution_time += start.elapsed();

        result
    }

    fn authorize_inner(&mut self, mut limits: AuthorizerLimits) -> Result<usize, error::Token> {
        let start = Instant::now();
        let time_limit = start + limits.max_time;
        let mut current_iterations = self.world.iterations;

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

        limits.max_time = time_limit - Instant::now();
        self.world.run_with_limits(&self.symbols, limits.clone())?;

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
                    )?,
                    CheckKind::All => {
                        self.world
                            .query_match_all(query, &rule_trusted_origins, &self.symbols)?
                    }
                    CheckKind::Reject => !self.world.query_match(
                        query,
                        usize::MAX,
                        &rule_trusted_origins,
                        &self.symbols,
                    )?,
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
                        )?,
                        CheckKind::All => self.world.query_match_all(
                            query.clone(),
                            &rule_trusted_origins,
                            &self.symbols,
                        )?,
                        CheckKind::Reject => !self.world.query_match(
                            query.clone(),
                            0,
                            &rule_trusted_origins,
                            &self.symbols,
                        )?,
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
                        rule: self.symbols.print_check(check),
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

                let res = self.world.query_match(
                    query,
                    usize::MAX,
                    &rule_trusted_origins,
                    &self.symbols,
                )?;

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
            for (i, block) in (blocks[1..]).iter().enumerate() {
                let block_trusted_origins = TrustedOrigins::from_scopes(
                    &block.scopes,
                    &TrustedOrigins::default(),
                    i + 1,
                    &self.public_key_to_block_id,
                );

                limits.max_time = time_limit - Instant::now();
                limits.max_iterations -= self.world.iterations - current_iterations;
                current_iterations = self.world.iterations;

                self.world.run_with_limits(&self.symbols, limits.clone())?;

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
                            )?,
                            CheckKind::All => self.world.query_match_all(
                                query.clone(),
                                &rule_trusted_origins,
                                &self.symbols,
                            )?,
                            CheckKind::Reject => !self.world.query_match(
                                query.clone(),
                                i + 1,
                                &rule_trusted_origins,
                                &self.symbols,
                            )?,
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
                            rule: self.symbols.print_check(check),
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
        self.to_string()
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
            let _ = writeln!(f);
        }

        for rule in &rules {
            let _ = writeln!(f, "{rule};");
        }
        if !rules.is_empty() {
            let _ = writeln!(f);
        }

        for check in &checks {
            let _ = writeln!(f, "{check};");
        }
        if !checks.is_empty() {
            let _ = writeln!(f);
        }

        for policy in &policies {
            let _ = writeln!(f, "{policy};");
        }
        f
    }
}

impl std::fmt::Display for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut has_facts = false;
        let mut all_facts = BTreeMap::new();
        for (origin, factset) in &self.world.facts.inner {
            let mut facts = HashSet::new();
            for fact in factset {
                facts.insert(self.symbols.print_fact(fact));
            }

            has_facts = has_facts || !facts.is_empty();
            all_facts.insert(origin, facts);
        }

        let builder_facts = self
            .authorizer_block_builder
            .facts
            .iter()
            .map(|f| f.to_string())
            .collect::<HashSet<_>>();
        has_facts = has_facts || !builder_facts.is_empty();
        let mut authorizer_origin = Origin::default();
        authorizer_origin.insert(usize::MAX);
        match all_facts.get_mut(&authorizer_origin) {
            Some(e) => {
                e.extend(builder_facts);
            }
            None => {
                all_facts.insert(&authorizer_origin, builder_facts);
            }
        }

        if has_facts {
            writeln!(f, "// Facts:")?;
        }

        for (origin, factset) in &all_facts {
            let mut facts = factset.iter().collect::<Vec<_>>();
            facts.sort();

            if !facts.is_empty() {
                writeln!(f, "// origin: {origin}")?;
            }

            for fact in facts {
                writeln!(f, "{};", fact)?;
            }
        }

        if has_facts {
            writeln!(f)?;
        }

        let mut has_rules = false;
        let mut rules_map: BTreeMap<usize, HashSet<String>> = BTreeMap::new();
        for ruleset in self.world.rules.inner.values() {
            has_rules = has_rules || !ruleset.is_empty();
            for (origin, rule) in ruleset {
                rules_map
                    .entry(*origin)
                    .or_default()
                    .insert(self.symbols.print_rule(rule));
            }
        }

        let builder_rules = self
            .authorizer_block_builder
            .rules
            .iter()
            .map(|rule| rule.to_string())
            .collect::<HashSet<_>>();
        has_rules = has_rules || !builder_rules.is_empty();

        rules_map
            .entry(usize::MAX)
            .or_default()
            .extend(builder_rules);

        if has_rules {
            writeln!(f, "// Rules:")?;
        }

        for (origin, rule_list) in &rules_map {
            if !rule_list.is_empty() {
                if *origin == usize::MAX {
                    writeln!(f, "// origin: authorizer")?;
                } else {
                    writeln!(f, "// origin: {origin}")?;
                }
            }

            let mut sorted_rule_list = rule_list.iter().collect::<Vec<_>>();
            sorted_rule_list.sort();
            for rule in sorted_rule_list {
                writeln!(f, "{};", rule)?;
            }
        }

        if has_rules {
            writeln!(f)?;
        }

        let mut has_checks = false;
        let mut checks_map: BTreeMap<usize, Vec<String>> = Default::default();

        if let Some(blocks) = &self.blocks {
            for (i, block) in blocks.iter().enumerate() {
                let entry = checks_map.entry(i).or_default();
                has_checks = has_checks || !&block.checks.is_empty();
                for check in &block.checks {
                    entry.push(self.symbols.print_check(check));
                }
            }
        }

        let authorizer_entry = checks_map.entry(usize::MAX).or_default();

        has_checks = has_checks || !&self.authorizer_block_builder.checks.is_empty();
        for check in &self.authorizer_block_builder.checks {
            authorizer_entry.push(check.to_string());
        }

        if has_checks {
            writeln!(f, "// Checks:")?;
        }

        for (origin, checks) in checks_map {
            if !checks.is_empty() {
                if origin == usize::MAX {
                    writeln!(f, "// origin: authorizer")?;
                } else {
                    writeln!(f, "// origin: {origin}")?;
                }
            }

            for check in checks {
                writeln!(f, "{};", &check)?;
            }
        }

        if has_checks {
            writeln!(f)?;
        }

        if !self.policies.is_empty() {
            writeln!(f, "// Policies:")?;
        }
        for policy in self.policies.iter() {
            writeln!(f, "{policy};")?;
        }

        Ok(())
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

pub type AuthorizerLimits = RunLimits;

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
    use std::time::Duration;

    use crate::{
        builder::{Algorithm, BiscuitBuilder, BlockBuilder},
        KeyPair,
    };

    use super::*;

    #[test]
    fn empty_authorizer() {
        let mut authorizer = Authorizer::new();
        authorizer.add_policy("allow if true").unwrap();
        assert_eq!(
            authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            }),
            Ok(0)
        );
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
                crate::builder::Algorithm::Ed25519,
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
        let keypair = KeyPair::new(Algorithm::Ed25519);
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
        let keypair = KeyPair::new(Algorithm::Ed25519);
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
        let root = KeyPair::new(Algorithm::Ed25519);
        let external = KeyPair::new(Algorithm::Ed25519);

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
        let serialized = biscuit2.to_vec().unwrap();
        let biscuit2 = Biscuit::from(serialized, root.public()).unwrap();

        let mut authorizer = Authorizer::new();
        let external2 = KeyPair::new(Algorithm::Ed25519);

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

        authorizer.set_limits(AuthorizerLimits {
            max_time: Duration::from_millis(10), //Set 10 milliseconds as the maximum time allowed for the authorization due to "cheap" worker on GitHub Actions
            ..Default::default()
        });

        let res = authorizer.authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        });
        println!("world after:\n{}", authorizer.print_world());

        res.unwrap();

        // authorizer facts are always visible, no matter what
        let authorizer_facts: Vec<Fact> = authorizer
            .query_with_limits(
                "authorizer(true) <- authorizer(true)",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(authorizer_facts.len(), 1);

        // authority facts are visible by default
        let authority_facts: Vec<Fact> = authorizer
            .query_with_limits(
                "right($right) <- right($right)",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(authority_facts.len(), 1);

        // authority facts are not visible if
        // there is an explicit rule scope annotation that does
        // not cover previous or authority
        let authority_facts_untrusted: Vec<Fact> = authorizer
            .query_with_limits(
                {
                    let mut r: Rule = "right($right) <- right($right) trusting {external}"
                        .try_into()
                        .unwrap();
                    r.set_scope("external", external.public()).unwrap();
                    r
                },
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(authority_facts_untrusted.len(), 0);

        // block facts are not visible by default
        let block_facts_untrusted: Vec<Fact> = authorizer
            .query_with_limits(
                "group($group) <- group($group)",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(block_facts_untrusted.len(), 0);

        // block facts are visible if trusted
        let block_facts_trusted: Vec<Fact> = authorizer
            .query_with_limits(
                {
                    let mut r: Rule = "group($group) <- group($group) trusting {external}"
                        .try_into()
                        .unwrap();
                    r.set_scope("external", external.public()).unwrap();
                    r
                },
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(block_facts_trusted.len(), 1);

        // block facts are visible by default with query_all
        let block_facts_query_all: Vec<Fact> = authorizer
            .query_all_with_limits(
                "group($group) <- group($group)",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(block_facts_query_all.len(), 1);

        // block facts are not visible with query_all if the query has an explicit
        // scope annotation that does not trust them
        let block_facts_query_all_explicit: Vec<Fact> = authorizer
            .query_all_with_limits(
                "group($group) <- group($group) trusting authority",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(block_facts_query_all_explicit.len(), 0);
    }

    #[test]
    fn authorizer_display_before_and_after_authorization() {
        let root = KeyPair::new(Algorithm::Ed25519);

        let mut token_builder = BiscuitBuilder::new();
        token_builder
            .add_code(
                r#"
            authority_fact(true);
            authority_rule($v) <- authority_fact($v);
            check if authority_fact(true), authority_rule(true);
        "#,
            )
            .unwrap();
        let token = token_builder.build(&root).unwrap();

        let mut authorizer = token.authorizer().unwrap();
        authorizer
            .add_code(
                r#"
          authorizer_fact(true);
          authorizer_rule($v) <- authorizer_fact($v);
          check if authorizer_fact(true), authorizer_rule(true);
          allow if true;
        "#,
            )
            .unwrap();
        let output_before_authorization = authorizer.to_string();

        assert!(
            output_before_authorization.contains("authorizer_fact(true)"),
            "Authorizer.to_string() displays authorizer facts even before running authorize()"
        );

        authorizer
            .authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            })
            .unwrap();

        let output_after_authorization = authorizer.to_string();
        assert!(
            output_after_authorization.contains("authorizer_rule(true)"),
            "Authorizer.to_string() displays generated facts after running authorize()"
        );

        assert_eq!(
            r#"// Facts:
// origin: 0
authority_fact(true);
authority_rule(true);
// origin: authorizer
authorizer_fact(true);
authorizer_rule(true);

// Rules:
// origin: 0
authority_rule($v) <- authority_fact($v);
// origin: authorizer
authorizer_rule($v) <- authorizer_fact($v);

// Checks:
// origin: 0
check if authority_fact(true), authority_rule(true);
// origin: authorizer
check if authorizer_fact(true), authorizer_rule(true);

// Policies:
allow if true;
"#,
            output_after_authorization
        );
    }

    #[test]
    fn empty_authorizer_display() {
        let authorizer = Authorizer::new();
        assert_eq!("", authorizer.to_string())
    }
}
