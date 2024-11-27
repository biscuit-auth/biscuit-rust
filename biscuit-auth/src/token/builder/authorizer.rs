use std::{
    collections::HashMap,
    convert::TryInto,
    time::{Instant, SystemTime},
};

use crate::{
    builder::Convert,
    builder_ext::{AuthorizerExt, BuilderExt},
    datalog::{ExternFunc, Origin, SymbolTable, TrustedOrigins, World},
    error,
    token::{self, Block},
    Authorizer, AuthorizerLimits, Biscuit, PublicKey,
};

use super::{BlockBuilder, Check, Fact, Policy, Rule, Scope, Term};

#[derive(Clone, Debug, Default)]
pub struct AuthorizerBuilder<'a> {
    authorizer_block_builder: BlockBuilder,
    policies: Vec<Policy>,
    extern_funcs: HashMap<String, ExternFunc>,
    limits: AuthorizerLimits,
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
        self.authorizer_block_builder.add_fact(fact)
    }

    pub fn add_rule<R: TryInto<Rule>>(&mut self, rule: R) -> Result<(), error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        self.authorizer_block_builder.add_rule(rule)
    }

    pub fn add_check<C: TryInto<Check>>(&mut self, check: C) -> Result<(), error::Token>
    where
        error::Token: From<<C as TryInto<Check>>::Error>,
    {
        self.authorizer_block_builder.add_check(check)
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
        self.authorizer_block_builder
            .add_code_with_params(source, params, scope_params)
    }

    pub fn add_scope(&mut self, scope: Scope) {
        self.authorizer_block_builder.add_scope(scope);
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

    /// Sets the runtime limits of the authorizer
    ///
    /// Those limits cover all the executions under the `authorize`, `query` and `query_all` methods
    pub fn set_limits(&mut self, limits: AuthorizerLimits) {
        self.limits = limits;
    }

    /// Replaces the registered external functions
    pub fn set_extern_funcs(&mut self, extern_funcs: HashMap<String, ExternFunc>) {
        self.extern_funcs = extern_funcs;
    }

    /// Registers the provided external functions (possibly replacing already registered functions)
    pub fn register_extern_funcs(&mut self, extern_funcs: HashMap<String, ExternFunc>) {
        self.extern_funcs.extend(extern_funcs);
    }

    /// Registers the provided external function (possibly replacing an already registered function)
    pub fn register_extern_func(&mut self, name: String, func: ExternFunc) {
        self.extern_funcs.insert(name, func);
    }

    pub fn add_token(&mut self, token: &'a Biscuit) {
        self.token = Some(token);
    }

    pub fn build(self) -> Result<Authorizer, error::Token> {
        let mut world = World::new();
        world.extern_funcs = self.extern_funcs;

        let mut symbols = SymbolTable::new();
        let mut public_key_to_block_id: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut token_origins = TrustedOrigins::default();
        let mut blocks: Option<Vec<Block>> = None;

        // load the token if present
        if let Some(token) = self.token {
            for (i, block) in token.container.blocks.iter().enumerate() {
                if let Some(sig) = block.external_signature.as_ref() {
                    let new_key_id = symbols.public_keys.insert(&sig.public_key);

                    public_key_to_block_id
                        .entry(new_key_id as usize)
                        .or_default()
                        .push(i + 1);
                }
            }

            blocks = Some(
                token
                    .blocks()
                    .enumerate()
                    .map(|(i, block)| {
                        block.and_then(|mut b| {
                            load_and_translate_block(
                                &mut b,
                                i,
                                &token.symbols,
                                &mut symbols,
                                &mut public_key_to_block_id,
                                &mut world,
                            )?;
                            Ok(b)
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );

            token_origins = TrustedOrigins::from_scopes(
                &[token::Scope::Previous],
                &TrustedOrigins::default(),
                token.block_count(),
                &public_key_to_block_id,
            );
        }
        let mut authorizer_origin = Origin::default();
        authorizer_origin.insert(usize::MAX);

        let authorizer_scopes: Vec<token::Scope> = self
            .authorizer_block_builder
            .scopes
            .clone()
            .iter()
            .map(|s| s.convert(&mut symbols))
            .collect();

        let authorizer_trusted_origins = TrustedOrigins::from_scopes(
            &authorizer_scopes,
            &TrustedOrigins::default(),
            usize::MAX,
            &public_key_to_block_id,
        );
        for fact in &self.authorizer_block_builder.facts {
            world
                .facts
                .insert(&authorizer_origin, fact.convert(&mut symbols));
        }

        for rule in &self.authorizer_block_builder.rules {
            let rule = rule.convert(&mut symbols);

            let rule_trusted_origins = TrustedOrigins::from_scopes(
                &rule.scopes,
                &authorizer_trusted_origins,
                usize::MAX,
                &public_key_to_block_id,
            );

            world.rules.insert(usize::MAX, &rule_trusted_origins, rule);
        }

        let start = Instant::now();
        world.run_with_limits(&symbols, self.limits.clone())?;
        let execution_time = start.elapsed();

        Ok(Authorizer {
            authorizer_block_builder: self.authorizer_block_builder,
            world,
            symbols,
            token_origins,
            policies: self.policies,
            blocks,
            public_key_to_block_id,
            limits: self.limits,
            execution_time,
        })
    }
}

/// we need to modify the block loaded from the token, because the authorizer's and the token's symbol table can differ
fn load_and_translate_block(
    block: &mut Block,
    i: usize,
    token_symbols: &SymbolTable,
    authorizer_symbols: &mut SymbolTable,
    public_key_to_block_id: &mut HashMap<usize, Vec<usize>>,
    world: &mut World,
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
        *scope = crate::token::builder::Scope::convert_from(scope, &block_symbols)
            .map(|s| s.convert(authorizer_symbols))?;
    }

    let block_trusted_origins = TrustedOrigins::from_scopes(
        &block.scopes,
        &TrustedOrigins::default(),
        i,
        &public_key_to_block_id,
    );

    for fact in block.facts.iter_mut() {
        *fact = Fact::convert_from(fact, &block_symbols)?.convert(authorizer_symbols);
        world.facts.insert(&block_origin, fact.clone());
    }

    for rule in block.rules.iter_mut() {
        if let Err(_message) = rule.validate_variables(&block_symbols) {
            return Err(error::Logic::InvalidBlockRule(0, block_symbols.print_rule(rule)).into());
        }
        *rule = rule.translate(&block_symbols, authorizer_symbols)?;

        let rule_trusted_origins = TrustedOrigins::from_scopes(
            &rule.scopes,
            &block_trusted_origins,
            i,
            &public_key_to_block_id,
        );

        world.rules.insert(i, &rule_trusted_origins, rule.clone());
    }

    for check in block.checks.iter_mut() {
        let c = Check::convert_from(check, &block_symbols)?;
        *check = c.convert(authorizer_symbols);
    }

    Ok(())
}

impl<'a> BuilderExt for AuthorizerBuilder<'a> {
    fn add_resource(&mut self, name: &str) {
        self.authorizer_block_builder.add_resource(name);
    }
    fn check_resource(&mut self, name: &str) {
        self.authorizer_block_builder.check_resource(name);
    }
    fn add_operation(&mut self, name: &str) {
        self.authorizer_block_builder.add_operation(name);
    }
    fn check_operation(&mut self, name: &str) {
        self.authorizer_block_builder.check_operation(name);
    }
    fn check_resource_prefix(&mut self, prefix: &str) {
        self.authorizer_block_builder.check_resource_prefix(prefix);
    }

    fn check_resource_suffix(&mut self, suffix: &str) {
        self.authorizer_block_builder.check_resource_suffix(suffix);
    }

    fn check_expiration_date(&mut self, exp: SystemTime) {
        self.authorizer_block_builder.check_expiration_date(exp);
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
