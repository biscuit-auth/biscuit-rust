use std::{collections::HashMap, convert::TryInto, time::SystemTime};

use crate::{
    builder_ext::{AuthorizerExt, BuilderExt},
    error, Authorizer, Biscuit, PublicKey,
};

use super::{BlockBuilder, Check, Fact, Policy, Rule, Scope, Term};

#[derive(Clone, Debug, Default)]
pub struct AuthorizerBuilder<'a> {
    block: BlockBuilder,
    policies: Vec<Policy>,
    token: Option<&'a Biscuit>,
}

impl<'a> AuthorizerBuilder<'a> {
    pub fn new() -> AuthorizerBuilder<'a> {
        AuthorizerBuilder::default()
    }

    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token>
    where
        error::Token: From<<F as TryInto<Fact>>::Error>,
    {
        self.block.add_fact(fact)
    }

    pub fn add_rule<R: TryInto<Rule>>(&mut self, rule: R) -> Result<(), error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        self.block.add_rule(rule)
    }

    pub fn add_check<C: TryInto<Check>>(&mut self, check: C) -> Result<(), error::Token>
    where
        error::Token: From<<C as TryInto<Check>>::Error>,
    {
        self.block.add_check(check)
    }

    pub fn add_code<T: AsRef<str>>(&mut self, source: T) -> Result<(), error::Token> {
        self.add_code_with_params(source, HashMap::new(), HashMap::new())
    }

    /// Add datalog code to the builder, performing parameter subsitution as required
    /// Unknown parameters are ignored
    pub fn add_code_with_params<T: AsRef<str>>(
        &mut self,
        source: T,
        params: HashMap<String, Term>,
        scope_params: HashMap<String, PublicKey>,
    ) -> Result<(), error::Token> {
        self.block
            .add_code_with_params(source, params, scope_params)
    }

    pub fn add_scope(&mut self, scope: Scope) {
        self.block.add_scope(scope);
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

    pub fn add_token(&mut self, token: &'a Biscuit) {
        self.token = Some(token);
    }

    pub fn build(self) -> Result<Authorizer, error::Token> {
        let authorizer = Authorizer::new();
        Ok(authorizer)
    }
}

impl<'a> BuilderExt for AuthorizerBuilder<'a> {
    fn add_resource(&mut self, name: &str) {
        self.block.add_resource(name);
    }
    fn check_resource(&mut self, name: &str) {
        self.block.check_resource(name);
    }
    fn add_operation(&mut self, name: &str) {
        self.block.add_operation(name);
    }
    fn check_operation(&mut self, name: &str) {
        self.block.check_operation(name);
    }
    fn check_resource_prefix(&mut self, prefix: &str) {
        self.block.check_resource_prefix(prefix);
    }

    fn check_resource_suffix(&mut self, suffix: &str) {
        self.block.check_resource_suffix(suffix);
    }

    fn check_expiration_date(&mut self, exp: SystemTime) {
        self.block.check_expiration_date(exp);
    }
}

impl<'a> AuthorizerExt for AuthorizerBuilder<'a> {
    fn add_allow_all(&mut self) {
        self.add_policy("allow if true").unwrap();
    }
    fn add_deny_all(&mut self) {
        self.add_policy("deny if true").unwrap();
    }
}
