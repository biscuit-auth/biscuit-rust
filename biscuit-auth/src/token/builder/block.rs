use super::{Block, Check, Convert, Fact, Rule, Scope, Term};
use crate::crypto::PublicKey;
use crate::datalog::{get_schema_version, SymbolTable};
use crate::error;
use biscuit_parser::parser::parse_block_source;

use std::{
    collections::HashMap,
    convert::TryInto,
    fmt::{self},
};

/// creates a Block content to append to an existing token
#[derive(Clone, Debug, Default)]
pub struct BlockBuilder {
    pub facts: Vec<Fact>,
    pub rules: Vec<Rule>,
    pub checks: Vec<Check>,
    pub scopes: Vec<Scope>,
    pub context: Option<String>,
}

impl BlockBuilder {
    pub fn new() -> BlockBuilder {
        BlockBuilder::default()
    }

    pub fn merge(&mut self, mut other: BlockBuilder) {
        self.facts.append(&mut other.facts);
        self.rules.append(&mut other.rules);
        self.checks.append(&mut other.checks);

        if let Some(c) = other.context {
            self.set_context(c);
        }
    }

    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token>
    where
        error::Token: From<<F as TryInto<Fact>>::Error>,
    {
        let fact = fact.try_into()?;
        fact.validate()?;

        self.facts.push(fact);
        Ok(())
    }

    pub fn add_rule<R: TryInto<Rule>>(&mut self, rule: R) -> Result<(), error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let rule = rule.try_into()?;
        rule.validate_parameters()?;
        self.rules.push(rule);
        Ok(())
    }

    pub fn add_check<C: TryInto<Check>>(&mut self, check: C) -> Result<(), error::Token>
    where
        error::Token: From<<C as TryInto<Check>>::Error>,
    {
        let check = check.try_into()?;
        check.validate_parameters()?;
        self.checks.push(check);
        Ok(())
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
        let input = source.as_ref();

        let source_result = parse_block_source(input).map_err(|e| {
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
            self.facts.push(fact);
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
            self.rules.push(rule);
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
            self.checks.push(check);
        }

        Ok(())
    }

    pub fn add_scope(&mut self, scope: Scope) {
        self.scopes.push(scope);
    }

    pub fn set_context(&mut self, context: String) {
        self.context = Some(context);
    }

    pub(crate) fn build(self, mut symbols: SymbolTable) -> Block {
        let symbols_start = symbols.current_offset();
        let public_keys_start = symbols.public_keys.current_offset();

        let mut facts = Vec::new();
        for fact in self.facts {
            facts.push(fact.convert(&mut symbols));
        }

        let mut rules = Vec::new();
        for rule in &self.rules {
            rules.push(rule.convert(&mut symbols));
        }

        let mut checks = Vec::new();
        for check in &self.checks {
            checks.push(check.convert(&mut symbols));
        }

        let mut scopes = Vec::new();
        for scope in &self.scopes {
            scopes.push(scope.convert(&mut symbols));
        }

        let new_syms = symbols.split_at(symbols_start);
        let public_keys = symbols.public_keys.split_at(public_keys_start);
        let schema_version = get_schema_version(&facts, &rules, &checks, &scopes);

        Block {
            symbols: new_syms,
            facts,
            rules,
            checks,
            context: self.context,
            version: schema_version.version(),
            external_key: None,
            public_keys,
            scopes,
        }
    }

    pub(crate) fn convert_from(
        block: &Block,
        symbols: &SymbolTable,
    ) -> Result<Self, error::Format> {
        Ok(BlockBuilder {
            facts: block
                .facts
                .iter()
                .map(|f| Fact::convert_from(f, symbols))
                .collect::<Result<Vec<Fact>, error::Format>>()?,
            rules: block
                .rules
                .iter()
                .map(|r| Rule::convert_from(r, symbols))
                .collect::<Result<Vec<Rule>, error::Format>>()?,
            checks: block
                .checks
                .iter()
                .map(|c| Check::convert_from(c, symbols))
                .collect::<Result<Vec<Check>, error::Format>>()?,
            scopes: block
                .scopes
                .iter()
                .map(|s| Scope::convert_from(s, symbols))
                .collect::<Result<Vec<Scope>, error::Format>>()?,
            context: block.context.clone(),
        })
    }

    // still used in tests but does not make sense for the public API
    #[cfg(test)]
    pub(crate) fn check_right(&mut self, right: &str) {
        use crate::builder::{pred, string, var};

        use super::rule;

        let term = string(right);
        let check = rule(
            "check_right",
            &[string(right)],
            &[
                pred("resource", &[var("resource_name")]),
                pred("operation", &[term]),
                pred("right", &[var("resource_name"), string(right)]),
            ],
        );

        let _ = self.add_check(check);
    }
}

impl fmt::Display for BlockBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for mut fact in self.facts.clone().into_iter() {
            fact.apply_parameters();
            writeln!(f, "{};", &fact)?;
        }
        for mut rule in self.rules.clone().into_iter() {
            rule.apply_parameters();
            writeln!(f, "{};", &rule)?;
        }
        for mut check in self.checks.clone().into_iter() {
            check.apply_parameters();
            writeln!(f, "{};", &check)?;
        }
        Ok(())
    }
}
