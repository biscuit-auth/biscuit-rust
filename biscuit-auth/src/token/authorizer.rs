//! Authorizer structure and associated functions
use super::builder::{
    constrained_rule, date, fact, pred, rule, string, var, Binary, Check, Expression, Fact, Op,
    Policy, PolicyKind, Rule, Term,
};
use super::builder_ext::{AuthorizerExt, BuilderExt};
use super::{Biscuit, Block};
use crate::builder::Convert;
use crate::crypto::PublicKey;
use crate::datalog::{self, FactSet, Origin, RuleSet, RunLimits};
use crate::error;
use crate::time::Instant;
use biscuit_parser::parser::parse_source;
use prost::Message;
use std::collections::{BTreeMap, HashSet};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    default::Default,
    time::{Duration, SystemTime},
};

/// used to check authorization policies on a token
///
/// can be created from [Biscuit::authorizer] or [Authorizer::new]
#[derive(Clone)]
pub struct Authorizer<'t> {
    world: datalog::World,
    pub(crate) symbols: datalog::SymbolTable,
    checks: Vec<Check>,
    token_checks: Vec<Vec<datalog::Check>>,
    policies: Vec<Policy>,
    token: Option<&'t Biscuit>,
    blocks: Vec<Block>,
}

impl<'t> Authorizer<'t> {
    pub(crate) fn from_token(token: &'t Biscuit) -> Result<Self, error::Token> {
        let mut v = Authorizer::new()?;
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
    pub fn new() -> Result<Self, error::Logic> {
        let world = datalog::World::new();
        let symbols = super::default_symbol_table();

        Ok(Authorizer {
            world,
            symbols,
            checks: vec![],
            token_checks: vec![],
            policies: vec![],
            token: None,
            blocks: vec![],
        })
    }

    /// creates an `Authorizer` from a serialized [crate::format::schema::AuthorizerPolicies]
    pub fn from(slice: &[u8]) -> Result<Self, error::Token> {
        let data = crate::format::schema::AuthorizerPolicies::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        let AuthorizerPolicies {
            version: _,
            symbols,
            mut facts,
            mut rules,
            mut checks,
            policies,
        } = crate::format::convert::proto_authorizer_to_authorizer(&data)?;

        let mut origin = Origin::default();
        origin.insert(0);
        let mut f = FactSet::default();
        let mut r = RuleSet::default();

        for fact in facts.drain(..) {
            f.insert(&origin, fact);
        }

        for rule in rules.drain(..) {
            r.insert(&origin, rule);
        }

        let world = datalog::World { facts: f, rules: r };
        let checks = checks
            .drain(..)
            .map(|c| Check::convert_from(&c, &symbols))
            .collect::<Result<Vec<_>, error::Format>>()?;

        Ok(Authorizer {
            world,
            symbols,
            checks,
            token_checks: vec![],
            policies,
            token: None,
            blocks: vec![],
        })
    }

    /// add a token to an empty authorizer
    pub fn add_token(&mut self, token: &'t Biscuit) -> Result<(), error::Token> {
        if self.token.is_some() {
            return Err(error::Logic::AuthorizerNotEmpty.into());
        }
        //FIXME: can the authorizer already have a set of known public keys?
        self.symbols
            .public_keys
            .extend(&token.symbols.public_keys)?;

        let mut blocks = Vec::new();

        let authority = token.block(0)?;
        let origin = authority.origins(0, Some(&token.public_key_to_block_id));

        // add authority facts and rules right away to make them available to queries
        for fact in authority.facts.iter().cloned() {
            let fact = Fact::convert_from(&fact, &token.symbols)?.convert(&mut self.symbols);
            self.world.facts.insert(&origin, fact);
        }

        for rule in authority.rules.iter().cloned() {
            if let Err(_message) = rule.validate_variables(&token.symbols) {
                return Err(
                    error::Logic::InvalidBlockRule(0, token.symbols.print_rule(&rule)).into(),
                );
            }

            let rule = rule.translate(&token.symbols, &mut self.symbols)?;
            if rule.scopes.is_empty() {
                self.world.rules.insert(&origin, rule);
            } else {
                let origin = rule.origins(0, Some(&token.public_key_to_block_id));
                self.world.rules.insert(&origin, rule);
            }
        }

        blocks.push(authority);
        for i in 1..token.block_count() {
            let block = token.block(i)?;

            // if it is a 3rd party block, it should not affect the main symbol table
            let block_symbols = if block.external_key.is_none() {
                &token.symbols
            } else {
                &block.symbols
            };

            let origin = block.origins(i, Some(&token.public_key_to_block_id));

            for fact in block.facts.iter().cloned() {
                let fact = Fact::convert_from(&fact, &block_symbols)?.convert(&mut self.symbols);
                self.world.facts.insert(&origin, fact);
            }

            for rule in block.rules.iter().cloned() {
                if let Err(_message) = rule.validate_variables(&token.symbols) {
                    return Err(
                        error::Logic::InvalidBlockRule(0, token.symbols.print_rule(&rule)).into(),
                    );
                }
                let rule = rule.translate(&block_symbols, &mut self.symbols)?;

                if rule.scopes.is_empty() {
                    self.world.rules.insert(&origin, rule);
                } else {
                    let origin = rule.origins(i, Some(&token.public_key_to_block_id));

                    self.world.rules.insert(&origin, rule);
                }
            }

            blocks.push(block);
        }

        self.blocks = blocks;
        self.token = Some(token);

        Ok(())
    }

    /// serializes a authorizer's content
    ///
    /// you can use this to save a set of policies and load them quickly before
    /// verification, or to store a verification context to debug it later
    pub fn save(&self) -> Result<Vec<u8>, error::Token> {
        let mut symbols = self.symbols.clone();
        let mut checks: Vec<datalog::Check> = self
            .checks
            .iter()
            .map(|c| c.convert(&mut symbols))
            .collect();
        for block_checks in &self.token_checks {
            checks.extend_from_slice(&block_checks[..]);
        }

        todo!();
        /*
        let policies = AuthorizerPolicies {
            version: crate::token::MAX_SCHEMA_VERSION,
            symbols,
            //FIXME
            facts: self.world.facts.iter().cloned().collect(),
            rules: self.world.rules.clone(),
            checks,
            policies: self.policies.clone(),
        };

        let proto = crate::format::convert::authorizer_to_proto_authorizer(&policies);

        let mut v = Vec::new();

        proto
            .encode(&mut v)
            .map(|_| v)
            .map_err(|e| error::Format::SerializationError(format!("serialization error: {:?}", e)))
            .map_err(error::Token::Format)
            */
    }

    /// add a fact to the authorizer
    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token>
    where
        error::Token: From<<F as TryInto<Fact>>::Error>,
    {
        let fact = fact.try_into()?;
        fact.validate()?;

        let mut origin = Origin::default();
        origin.insert(0);
        self.world
            .facts
            .insert(&origin, fact.convert(&mut self.symbols));
        Ok(())
    }

    /// add a rule to the authorizer
    pub fn add_rule<R: TryInto<Rule>>(&mut self, rule: R) -> Result<(), error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let rule = rule.try_into()?;
        rule.validate_parameters()?;
        let mut origin = Origin::default();
        origin.insert(0);
        self.world
            .rules
            .insert(&origin, rule.convert(&mut self.symbols));
        Ok(())
    }

    /// adds some datalog code to the authorizer
    ///
    /// ```rust
    /// extern crate biscuit_auth as biscuit;
    ///
    /// use biscuit::Authorizer;
    ///
    /// let mut authorizer = Authorizer::new().unwrap();
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
        let input = source.as_ref();

        let source_result = parse_source(input).map_err(|e| {
            let e2: biscuit_parser::error::LanguageError = e.into();
            e2
        })?;

        let mut origin = Origin::default();
        origin.insert(0);

        for (_, fact) in source_result.facts.into_iter() {
            let mut fact: Fact = fact.into();

            for (name, value) in &params {
                let res = match fact.set(&name, value) {
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

            self.world
                .facts
                .insert(&origin, fact.convert(&mut self.symbols));
        }

        for (_, rule) in source_result.rules.into_iter() {
            let mut rule: Rule = rule.into();
            for (name, value) in &params {
                let res = match rule.set(&name, value) {
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
                let res = match rule.set_scope(&name, *value) {
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
            self.world
                .rules
                .insert(&origin, rule.convert(&mut self.symbols));
        }

        for (_, check) in source_result.checks.into_iter() {
            let mut check: Check = check.into();
            for (name, value) in &params {
                let res = match check.set(&name, value) {
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
                let res = match check.set_scope(&name, *value) {
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
            self.checks.push(check);
        }

        for (_, policy) in source_result.policies.into_iter() {
            let mut policy: Policy = policy.into();
            for (name, value) in &params {
                let res = match policy.set(&name, value) {
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
                let res = match policy.set_scope(&name, *value) {
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
    /// let res: Vec<(String, i64)> = authorizer.query("data($name, $id) <- user($name, $id)", &[0].iter().collect()).unwrap();
    /// # assert_eq!(res.len(), 1);
    /// # assert_eq!(res[0].0, "John Doe");
    /// # assert_eq!(res[0].1, 42);
    /// ```
    pub fn query<R: TryInto<Rule>, T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: R,
        origin: &Origin,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        self.query_with_limits(rule, origin, AuthorizerLimits::default())
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// this only sees facts from the authorizer and the authority block
    ///
    /// this method can specify custom runtime limits
    pub fn query_with_limits<R: TryInto<Rule>, T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: R,
        origin: &Origin,
        limits: AuthorizerLimits,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let rule = rule.try_into()?;

        self.world
            .run_with_limits(&self.symbols, limits.into())
            .map_err(error::Token::RunLimit)?;
        let res = self
            .world
            .query_rule(rule.convert(&mut self.symbols), origin, &self.symbols);

        res //.drain(..)
            .inner
            .into_iter()
            .map(|(_, set)| set.into_iter())
            .flatten()
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
    /// let res: Vec<(String, i64)> = authorizer.query("data($name, $id) <- user($name, $id)",  &[0].iter().collect()).unwrap();
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
        let rule = rule.try_into()?;

        self.world
            .run_with_limits(&self.symbols, limits.into())
            .map_err(error::Token::RunLimit)?;
        let rule = rule.convert(&mut self.symbols);
        let origin = if let Some(t) = self.token {
            std::iter::repeat(())
                .enumerate()
                .take(t.block_count())
                .map(|(i, _)| i)
                .collect()
        } else {
            [0].iter().collect()
        };

        let res = self.world.query_rule(rule.clone(), &origin, &self.symbols);

        let r: HashSet<_> = res.into_iter().map(|(_, fact)| fact).collect();

        r.into_iter()
            .map(|f| Fact::convert_from(&f, &self.symbols))
            .map(|fact| {
                fact.map_err(error::Token::Format)
                    .and_then(|f| f.try_into().map_err(Into::into))
            })
            .collect::<Result<Vec<T>, _>>()
    }

    /// add a check to the authorizer
    pub fn add_check<C: TryInto<Check>>(&mut self, check: C) -> Result<(), error::Token>
    where
        error::Token: From<<C as TryInto<Check>>::Error>,
    {
        let check = check.try_into()?;
        check.validate_parameters()?;
        self.checks.push(check);
        Ok(())
    }

    /// adds a fact with the current time
    pub fn set_time(&mut self) {
        let fact = fact("time", &[date(&SystemTime::now())]);
        let mut origin = Origin::default();
        origin.insert(0);
        self.world
            .facts
            .insert(&origin, fact.convert(&mut self.symbols));
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
    pub fn authorize_with_limits(
        &mut self,
        limits: AuthorizerLimits,
    ) -> Result<usize, error::Token> {
        let start = Instant::now();
        let time_limit = start + limits.max_time;
        let mut errors = vec![];
        let mut policy_result: Option<Result<usize, usize>> = None;

        //FIXME: the authorizer should be generated with run limits
        // that are "consumed" after each use
        // Note: the authority facts and rules were already inserted
        // in add_token
        self.world
            .run_with_limits(&self.symbols, RunLimits::default())
            .map_err(error::Token::RunLimit)?;
        //self.world.rules.clear();

        let mut origin = Origin::default();
        origin.insert(0);

        for (i, check) in self.checks.iter().enumerate() {
            let c = check.convert(&mut self.symbols);
            let mut successful = false;

            for query in check.queries.iter() {
                let query = query.convert(&mut self.symbols);
                let origin = if query.scopes.is_empty() {
                    origin.clone()
                } else {
                    query.origins(0, self.token.as_ref().map(|t| &t.public_key_to_block_id))
                };
                let res = self.world.query_match(query, &origin, &self.symbols);

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

        if let Some(token) = self.token.as_ref() {
            let origin = self.blocks[0].origins(0, Some(&token.public_key_to_block_id));

            for (j, check) in self.blocks[0].checks.iter().enumerate() {
                let mut successful = false;

                let c = Check::convert_from(check, &token.symbols)?;
                let check = c.convert(&mut self.symbols);

                for query in check.queries.iter() {
                    let origin = if query.scopes.is_empty() {
                        origin.clone()
                    } else {
                        query.origins(0, self.token.as_ref().map(|t| &t.public_key_to_block_id))
                    };
                    let res = self
                        .world
                        .query_match(query.clone(), &origin, &self.symbols);

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
                let origin = if query.scopes.is_empty() {
                    origin.clone()
                } else {
                    query.origins(0, self.token.as_ref().map(|t| &t.public_key_to_block_id))
                };
                let res = self.world.query_match(query, &origin, &self.symbols);

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

        if let Some(token) = self.token.as_ref() {
            for (i, block) in (&self.blocks[1..]).iter().enumerate() {
                // if it is a 3rd party block, it should not affect the main symbol table
                let block_symbols = if block.external_key.is_none() {
                    &token.symbols
                } else {
                    &block.symbols
                };

                let origin = block.origins(i + 1, Some(&token.public_key_to_block_id));

                self.world
                    .run_with_limits(&self.symbols, RunLimits::default())
                    .map_err(error::Token::RunLimit)?;

                for (j, check) in block.checks.iter().enumerate() {
                    let mut successful = false;
                    let c = Check::convert_from(check, &block_symbols)?;
                    let check = c.convert(&mut self.symbols);

                    for query in check.queries.iter() {
                        let origin = if query.scopes.is_empty() {
                            origin.clone()
                        } else {
                            query.origins(
                                i + 1,
                                self.token.as_ref().map(|t| &t.public_key_to_block_id),
                            )
                        };

                        let res = self
                            .world
                            .query_match(query.clone(), &origin, &self.symbols);

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
                        .map(|r| self.symbols.print_rule(r))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        let mut checks = Vec::new();
        for (index, check) in self.checks.iter().enumerate() {
            checks.push(format!("Authorizer[{}]: {}", index, check));
        }

        for (i, block_checks) in self.token_checks.iter().enumerate() {
            for (j, check) in block_checks.iter().enumerate() {
                checks.push(format!(
                    "Block[{}][{}]: {}",
                    i,
                    j,
                    self.symbols.print_check(check)
                ));
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
        let mut checks = self.checks.clone();
        checks.extend(
            self.token_checks
                .iter()
                .flatten()
                .map(|c| Check::convert_from(c, &self.symbols).unwrap()),
        );

        (
            self.world
                .facts
                .iter_all()
                .map(|f| Fact::convert_from(f.1, &self.symbols))
                .collect::<Result<Vec<_>, error::Format>>()
                .unwrap(),
            self.world
                .rules
                .iter_all()
                .map(|r| Rule::convert_from(r.1, &self.symbols).unwrap())
                .collect(),
            checks,
            self.policies.clone(),
        )
    }

    pub fn dump_code(&self) -> String {
        let (facts, rules, checks, policies) = self.dump();
        let mut f = String::new();
        for fact in facts {
            f.push_str(&format!("{};\n", &fact));
        }
        for rule in rules {
            f.push_str(&format!("{};\n", &rule));
        }
        for check in checks {
            f.push_str(&format!("{};\n", &check));
        }
        for policy in policies {
            f.push_str(&format!("{};\n", &policy));
        }
        f
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizerPolicies {
    pub version: u32,
    /// list of symbols introduced by this block
    pub symbols: datalog::SymbolTable,
    /// list of facts provided by this block
    pub facts: Vec<datalog::Fact>,
    /// list of rules provided by blocks
    pub rules: Vec<datalog::Rule>,
    /// checks that the token and ambient data must validate
    pub checks: Vec<datalog::Check>,
    pub policies: Vec<Policy>,
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

impl BuilderExt for Authorizer<'_> {
    fn add_resource(&mut self, name: &str) {
        let f = fact("resource", &[string(name)]);
        let mut origin = Origin::default();
        origin.insert(0);
        self.world
            .facts
            .insert(&origin, f.convert(&mut self.symbols));
    }
    fn check_resource(&mut self, name: &str) {
        self.checks.push(Check {
            queries: vec![rule(
                "resource_check",
                &[string("resource_check")],
                &[pred("resource", &[string(name)])],
            )],
        });
    }
    fn add_operation(&mut self, name: &str) {
        let f = fact("operation", &[string(name)]);
        let mut origin = Origin::default();
        origin.insert(0);
        self.world
            .facts
            .insert(&origin, f.convert(&mut self.symbols));
    }
    fn check_operation(&mut self, name: &str) {
        self.checks.push(Check {
            queries: vec![rule(
                "operation_check",
                &[string("operation_check")],
                &[pred("operation", &[string(name)])],
            )],
        });
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

        self.checks.push(Check {
            queries: vec![check],
        });
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

        self.checks.push(Check {
            queries: vec![check],
        });
    }

    fn check_expiration_date(&mut self, exp: SystemTime) {
        let check = constrained_rule(
            "expiration",
            &[var("date")],
            &[pred("time", &[var("date")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("date")),
                    Op::Value(date(&exp)),
                    Op::Binary(Binary::LessOrEqual),
                ],
            }],
        );

        self.checks.push(Check {
            queries: vec![check],
        });
    }
}

impl AuthorizerExt for Authorizer<'_> {
    fn add_allow_all(&mut self) {
        self.add_policy("allow if true").unwrap();
    }
    fn add_deny_all(&mut self) {
        self.add_policy("deny if true").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_authorizer() {
        let mut authorizer = Authorizer::new().unwrap();
        authorizer.add_policy("allow if true").unwrap();
        assert_eq!(authorizer.authorize(), Ok(0));
    }

    #[test]
    fn parameter_substitution() {
        let mut authorizer = Authorizer::new().unwrap();
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
        let mut builder = Authorizer::new().unwrap();

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
        let mut builder = Authorizer::new().unwrap();
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
            .query(
                "data($name, $id) <- user($name, $id)",
                &[0].iter().collect(),
            )
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
        let res: Vec<(String,)> = authorizer
            .query("data($name) <- user($name)", &[0].iter().collect())
            .unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].0, "John Doe");
    }
}
