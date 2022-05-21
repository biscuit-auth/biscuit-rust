//! Authorizer structure and associated functions
use super::builder::{date, fact, Check, Fact, Policy, PolicyKind, Rule, Term};
use super::Biscuit;
use crate::datalog::{self, RunLimits};
use crate::error;
use crate::parser::parse_source;
use crate::time::Instant;
use prost::Message;
use std::{
    collections::{HashMap, HashSet},
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
    block_worlds: Vec<datalog::World>,
    pub(crate) symbols: datalog::SymbolTable,
    checks: Vec<Check>,
    token_checks: Vec<Vec<datalog::Check>>,
    policies: Vec<Policy>,
    token: Option<&'t Biscuit>,
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
            block_worlds: vec![],
            symbols,
            checks: vec![],
            token_checks: vec![],
            policies: vec![],
            token: None,
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
            rules,
            mut checks,
            policies,
        } = crate::format::convert::proto_authorizer_to_authorizer(&data)?;

        let world = datalog::World {
            facts: facts.drain(..).collect(),
            rules,
        };
        let checks = checks
            .drain(..)
            .map(|c| Check::convert_from(&c, &symbols))
            .collect();

        Ok(Authorizer {
            world,
            block_worlds: vec![],
            symbols,
            checks,
            token_checks: vec![],
            policies,
            token: None,
        })
    }

    /// add a token to an empty authorizer
    pub fn add_token(&mut self, token: &'t Biscuit) -> Result<(), error::Token> {
        if self.token.is_some() {
            return Err(error::Logic::AuthorizerNotEmpty.into());
        }

        // add authority facts and rules right away to make them available to queries
        for fact in token.authority.facts.iter().cloned() {
            let fact = Fact::convert_from(&fact, &token.symbols).convert(&mut self.symbols);
            self.world.facts.insert(fact);
        }

        for rule in token.authority.rules.iter().cloned() {
            let r = Rule::convert_from(&rule, &token.symbols);
            let rule = r.convert(&mut self.symbols);

            if let Err(_message) = r.validate_variables() {
                return Err(
                    error::Logic::InvalidBlockRule(0, token.symbols.print_rule(&rule)).into(),
                );
            }
        }

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

        let policies = AuthorizerPolicies {
            version: crate::token::MAX_SCHEMA_VERSION,
            symbols,
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
    }

    /// add a fact to the authorizer
    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token>
    where
        error::Token: From<<F as TryInto<Fact>>::Error>,
    {
        let fact = fact.try_into()?;
        fact.validate()?;

        self.world.facts.insert(fact.convert(&mut self.symbols));
        Ok(())
    }

    /// add a rule to the authorizer
    pub fn add_rule<R: TryInto<Rule>>(&mut self, rule: R) -> Result<(), error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let rule = rule.try_into()?;
        rule.validate_parameters()?;
        self.world.rules.push(rule.convert(&mut self.symbols));
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
        self.add_code_with_params(source, HashMap::new())
    }

    pub fn add_code_with_params<T: AsRef<str>>(
        &mut self,
        source: T,
        params: HashMap<String, Term>,
    ) -> Result<(), error::Token> {
        let input = source.as_ref();

        let source_result = parse_source(input)?;

        for (_, mut fact) in source_result.facts.into_iter() {
            for (name, value) in &params {
                let res = match fact.set(&name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(error::LanguageError::UnknownParameter(_))) => {
                        Ok(())
                    }
                    Err(e) => Err(e),
                };
                res?;
            }
            fact.validate()?;
            self.world.facts.insert(fact.convert(&mut self.symbols));
        }

        for (_, mut rule) in source_result.rules.into_iter() {
            for (name, value) in &params {
                let res = match rule.set(&name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(error::LanguageError::UnknownParameter(_))) => {
                        Ok(())
                    }
                    Err(e) => Err(e),
                };
                res?;
            }
            rule.validate_parameters()?;
            self.world.rules.push(rule.convert(&mut self.symbols));
        }

        for (_, mut check) in source_result.checks.into_iter() {
            for (name, value) in &params {
                let res = match check.set(&name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(error::LanguageError::UnknownParameter(_))) => {
                        Ok(())
                    }
                    Err(e) => Err(e),
                };
                res?;
            }
            check.validate_parameters()?;
            self.checks.push(check);
        }

        for (_, mut policy) in source_result.policies.into_iter() {
            for (name, value) in &params {
                let res = match policy.set(&name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(error::LanguageError::UnknownParameter(_))) => {
                        Ok(())
                    }
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
    /// this only sees facts from the authorizer and the authority block
    /// ```rust
    /// # use biscuit_auth::KeyPair;
    /// # use biscuit_auth::Biscuit;
    /// let keypair = KeyPair::new();
    /// let mut builder = Biscuit::builder(&keypair);
    /// builder.add_authority_fact("user(\"John Doe\", 42)");
    ///
    /// let biscuit = builder.build().unwrap();
    ///
    /// let mut authorizer = biscuit.authorizer().unwrap();
    /// let res: Vec<(String, i64)> = authorizer.query("data($name, $id) <- user($name, $id)").unwrap();
    /// # assert_eq!(res.len(), 1);
    /// # assert_eq!(res[0].0, "John Doe");
    /// # assert_eq!(res[0].1, 42);
    /// ```
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
        let rule = rule.try_into()?;

        self.world
            .run_with_limits(&self.symbols, limits.into())
            .map_err(error::Token::RunLimit)?;
        let mut res = self
            .world
            .query_rule(rule.convert(&mut self.symbols), &self.symbols);

        res.drain(..)
            .map(|f| Fact::convert_from(&f, &self.symbols))
            .map(|fact| fact.try_into().map_err(Into::into))
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
    /// let mut builder = Biscuit::builder(&keypair);
    /// builder.add_authority_fact("user(\"John Doe\", 42)");
    ///
    /// let biscuit = builder.build().unwrap();
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
        let rule = rule.try_into()?;

        self.world
            .run_with_limits(&self.symbols, limits.into())
            .map_err(error::Token::RunLimit)?;
        let rule = rule.convert(&mut self.symbols);
        let mut res = self.world.query_rule(rule.clone(), &self.symbols);

        let r: HashSet<_> = res
            .drain(..)
            .chain(
                self.block_worlds
                    .iter()
                    .map(|world| rule.apply(&world.facts, &self.symbols))
                    .flatten(),
            )
            .collect();

        r.into_iter()
            .map(|f| Fact::convert_from(&f, &self.symbols))
            .map(|fact| fact.try_into().map_err(Into::into))
            .collect()
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
        self.world.facts.insert(fact.convert(&mut self.symbols));
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
        self.world.rules.clear();

        for (i, check) in self.checks.iter().enumerate() {
            let c = check.convert(&mut self.symbols);
            let mut successful = false;

            for query in check.queries.iter() {
                let res = self
                    .world
                    .query_match(query.convert(&mut self.symbols), &self.symbols);

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
            for (j, check) in token.authority.checks.iter().enumerate() {
                let mut successful = false;

                let c = Check::convert_from(check, &token.symbols);
                let check = c.convert(&mut self.symbols);

                for query in check.queries.iter() {
                    let res = self.world.query_match(query.clone(), &self.symbols);

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
                let res = self
                    .world
                    .query_match(query.convert(&mut self.symbols), &self.symbols);

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
            for (i, block) in token.blocks.iter().enumerate() {
                let mut world = self.world.clone();

                // blocks cannot provide authority or ambient facts
                for fact in block.facts.iter().cloned() {
                    let fact = Fact::convert_from(&fact, &token.symbols).convert(&mut self.symbols);
                    world.facts.insert(fact);
                }

                for rule in block.rules.iter().cloned() {
                    let r = Rule::convert_from(&rule, &token.symbols);

                    if let Err(_message) = r.validate_variables() {
                        return Err(error::Logic::InvalidBlockRule(
                            i as u32,
                            token.symbols.print_rule(&rule),
                        )
                        .into());
                    }

                    let rule = r.convert(&mut self.symbols);
                    world.rules.push(rule);
                }

                world
                    .run_with_limits(&self.symbols, RunLimits::default())
                    .map_err(error::Token::RunLimit)?;
                world.rules.clear();

                for (j, check) in block.checks.iter().enumerate() {
                    let mut successful = false;
                    let c = Check::convert_from(check, &token.symbols);
                    let check = c.convert(&mut self.symbols);

                    for query in check.queries.iter() {
                        let res = world.query_match(query.clone(), &self.symbols);

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

                self.block_worlds.push(world);
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
        let mut facts = self
            .world
            .facts
            .iter()
            .map(|f| self.symbols.print_fact(f))
            .collect::<Vec<_>>();
        facts.sort();

        let mut rules = self
            .world
            .rules
            .iter()
            .map(|r| self.symbols.print_rule(r))
            .collect::<Vec<_>>();
        rules.sort();

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
                .map(|c| Check::convert_from(c, &self.symbols)),
        );

        (
            self.world
                .facts
                .iter()
                .chain(
                    self.block_worlds
                        .iter()
                        .map(|world| world.facts.iter())
                        .flatten(),
                )
                .map(|f| Fact::convert_from(f, &self.symbols))
                .collect(),
            self.world
                .rules
                .iter()
                .map(|r| Rule::convert_from(r, &self.symbols))
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
        authorizer
            .add_code_with_params(
                r#"
                  fact({p1}, "value");
                  rule($var, {p2}) <- fact($var, {p2});
                  check if {p3};
                  allow if {p3};
              "#,
                params,
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
            Err(error::Token::Language(error::LanguageError::Builder {
                invalid_parameters: vec!["p4".to_string()]
            }))
        );
        let mut rule = Rule::try_from(
            "fact($var1, {p2}) <- f1($var1, $var3), f2({p2}, $var3, {p4}), $var3.starts_with({p2})",
        )
        .unwrap();
        rule.set("p2", "hello").unwrap();
        let res = builder.add_rule(rule);
        assert_eq!(
            res,
            Err(error::Token::Language(error::LanguageError::Builder {
                invalid_parameters: vec!["p4".to_string()]
            }))
        );
        let mut check = Check::try_from("check if {p4}, {p3}").unwrap();
        check.set("p3", true).unwrap();
        let res = builder.add_check(check);
        assert_eq!(
            res,
            Err(error::Token::Language(error::LanguageError::Builder {
                invalid_parameters: vec!["p4".to_string()]
            }))
        );
        let mut policy = Policy::try_from("allow if {p4}, {p3}").unwrap();
        policy.set("p3", true).unwrap();

        let res = builder.add_policy(policy);
        assert_eq!(
            res,
            Err(error::Token::Language(error::LanguageError::Builder {
                invalid_parameters: vec!["p4".to_string()]
            }))
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
        );

        assert_eq!(
            res,
            Err(error::Token::Language(error::LanguageError::Builder {
                invalid_parameters: vec!["p3".to_string()]
            }))
        )
    }

    #[test]
    fn query_authorizer_from_token_tuple() {
        use crate::Biscuit;
        use crate::KeyPair;
        let keypair = KeyPair::new();
        let mut builder = Biscuit::builder(&keypair);
        builder
            .add_authority_fact("user(\"John Doe\", 42)")
            .unwrap();

        let biscuit = builder.build().unwrap();

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
        let mut builder = Biscuit::builder(&keypair);
        builder.add_authority_fact("user(\"John Doe\")").unwrap();

        let biscuit = builder.build().unwrap();

        let mut authorizer = biscuit.authorizer().unwrap();
        let res: Vec<(String,)> = authorizer.query("data($name) <- user($name)").unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].0, "John Doe");
    }
}
