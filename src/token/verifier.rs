use super::builder::{
    constrained_rule, date, fact, pred, s, string, Constraint, ConstraintKind, Fact,
    IntConstraint, Rule, Caveat, var,
};
use super::Biscuit;
use crate::datalog;
use crate::error;
use std::{convert::TryInto, time::{SystemTime, Duration}, default::Default};

#[derive(Clone)]
pub struct Verifier {
    world: datalog::World,
    symbols: datalog::SymbolTable,
    caveats: Vec<Caveat>,
    token_caveats: Vec<Vec<datalog::Caveat>>,
    has_token: bool,
}

impl Verifier {
    pub(crate) fn from_token(token: &Biscuit) -> Result<Self, error::Logic> {
        let world = token.generate_world(&token.symbols)?;
        let symbols = token.symbols.clone();

        Ok(Verifier {
            world,
            symbols,
            caveats: vec![],
            token_caveats: token.caveats(),
            has_token: true,
        })
    }

    pub fn new() -> Result<Self, error::Logic> {
        let world = datalog::World::new();
        let symbols = super::default_symbol_table();

        Ok(Verifier {
            world,
            symbols,
            caveats: vec![],
            token_caveats: vec![],
            has_token: false,
        })
    }

    pub fn add_token(&mut self, token: &Biscuit) -> Result<(), error::Logic> {
        if self.has_token {
            return Err(error::Logic::VerifierNotEmpty);
        } else {
            self.has_token = true;
        }

        let authority_index = self.symbols.get("authority").unwrap();
        let ambient_index = self.symbols.get("ambient").unwrap();

        for fact in token.authority.facts.iter().cloned() {
            if fact.predicate.ids[0] == datalog::ID::Symbol(ambient_index) {
                return Err(error::Logic::InvalidAuthorityFact(
                    token.symbols.print_fact(&fact),
                ));
            }

            let fact = Fact::convert_from(&fact, &token.symbols).convert(&mut self.symbols);
            self.world.facts.insert(fact);
        }

        for rule in token.authority.rules.iter().cloned() {
            let rule = Rule::convert_from(&rule, &token.symbols).convert(&mut self.symbols);
            self.world.rules.push(rule);
        }

        for (i, block) in token.blocks.iter().enumerate() {
            // blocks cannot provide authority or ambient facts
            for fact in block.facts.iter().cloned() {
                if fact.predicate.ids[0] == datalog::ID::Symbol(authority_index)
                    || fact.predicate.ids[0] == datalog::ID::Symbol(ambient_index)
                {
                    return Err(error::Logic::InvalidBlockFact(
                        i as u32,
                        token.symbols.print_fact(&fact),
                    ));
                }

                let fact = Fact::convert_from(&fact, &token.symbols).convert(&mut self.symbols);
                self.world.facts.insert(fact);
            }

            for rule in block.rules.iter().cloned() {
                // block rules cannot generate authority or ambient facts
                if rule.head.ids[0] == datalog::ID::Symbol(authority_index)
                    || rule.head.ids[0] == datalog::ID::Symbol(ambient_index)
                {
                    return Err(error::Logic::InvalidBlockRule(
                        i as u32,
                        token.symbols.print_rule(&rule),
                    ));
                }

                let rule = Rule::convert_from(&rule, &token.symbols).convert(&mut self.symbols);
                self.world.rules.push(rule);
            }
        }

        let mut token_caveats: Vec<Vec<datalog::Caveat>> = Vec::new();
        let caveats = token.authority.caveats.iter()
            .map(|c| Caveat::convert_from(&c, &token.symbols).convert(&mut self.symbols))
            .collect();
        token_caveats.push(caveats);

        for block in token.blocks.iter() {
            let caveats = block.caveats.iter()
                .map(|c| Caveat::convert_from(&c, &token.symbols).convert(&mut self.symbols))
                .collect();
            token_caveats.push(caveats);
        }

        self.token_caveats = token_caveats;
        Ok(())
    }

    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token> {
        let fact = fact.try_into().map_err(|_| error::Token::ParseError)?;
        self.world.facts.insert(fact.convert(&mut self.symbols));
        Ok(())
    }

    pub fn add_rule<R: TryInto<Rule>>(&mut self, rule: R) -> Result<(), error::Token> {
        let rule = rule.try_into().map_err(|_| error::Token::ParseError)?;
        self.world.rules.push(rule.convert(&mut self.symbols));
        Ok(())
    }

    pub fn query<R: TryInto<Rule>>(
        &mut self,
        rule: R,
    ) -> Result<Vec<Fact>, error::Token> {
        self.query_with_limits(rule, VerifierLimits::default())
    }

    pub fn query_with_limits<R: TryInto<Rule>>(
        &mut self,
        rule: R,
        limits: VerifierLimits
    ) -> Result<Vec<Fact>, error::Token> {
        let rule = rule.try_into().map_err(|_| error::Token::ParseError)?;
        self.world.run_with_limits(limits.into()).map_err(error::Token::RunLimit)?;
        let mut res = self.world.query_rule(rule.convert(&mut self.symbols));

        Ok(res
           .drain(..)
           .map(|f| Fact::convert_from(&f, &self.symbols))
           .collect())
    }

    /// verifier caveats
    pub fn add_caveat<R: TryInto<Caveat>>(&mut self, caveat: R) -> Result<(), error::Token> {
        let caveat = caveat.try_into().map_err(|_| error::Token::ParseError)?;
        self.caveats.push(caveat);
        Ok(())
    }

    pub fn add_resource(&mut self, resource: &str) {
        let fact = fact("resource", &[s("ambient"), string(resource)]);
        self.world.facts.insert(fact.convert(&mut self.symbols));
    }

    pub fn add_operation(&mut self, operation: &str) {
        let fact = fact("operation", &[s("ambient"), s(operation)]);
        self.world.facts.insert(fact.convert(&mut self.symbols));
    }

    pub fn set_time(&mut self) {
        let fact = fact("time", &[s("ambient"), date(&SystemTime::now())]);
        self.world.facts.insert(fact.convert(&mut self.symbols));
    }

    pub fn revocation_check(&mut self, ids: &[i64]) {
        let caveat = constrained_rule(
            "revocation_check",
            &[var("id")],
            &[pred("revocation_id", &[var("id")])],
            &[Constraint {
                id: "id".to_string(),
                kind: ConstraintKind::Integer(IntConstraint::NotIn(ids.iter().cloned().collect())),
            }],
        );
        let _ = self.add_caveat(caveat);
    }

    pub fn verify(&mut self) -> Result<(), error::Token> {
        self.verify_with_limits(VerifierLimits::default())
    }

    pub fn verify_with_limits(&mut self, limits: VerifierLimits) -> Result<(), error::Token> {
        let start = SystemTime::now();

        //FIXME: should check for the presence of any other symbol in the token
        if self.symbols.get("authority").is_none() || self.symbols.get("ambient").is_none() {
            return Err(error::Token::MissingSymbols);
        }

        self.world.run_with_limits(limits.clone().into()).map_err(error::Token::RunLimit)?;

        let time_limit = start + limits.max_time;

        let mut errors = vec![];
        for (i, caveat) in self.caveats.iter().enumerate() {
            let c = caveat.convert(&mut self.symbols);
            let mut successful = false;

            for query in caveat.queries.iter() {
                let res = self.world.query_rule(query.convert(&mut self.symbols));

                let now = SystemTime::now();
                if now >= time_limit {
                    return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                }

                if !res.is_empty() {
                    successful = true;
                    break;
                }
            }

            if !successful {
                errors.push(error::FailedCaveat::Verifier(error::FailedVerifierCaveat {
                    caveat_id: i as u32,
                    rule: self.symbols.print_caveat(&c),
                }));
            }
        }

        for (i, block_caveats) in self.token_caveats.iter().enumerate() {
            for (j, caveat) in block_caveats.iter().enumerate() {
                let mut successful = false;

                for query in caveat.queries.iter() {
                    let res = self.world.query_rule(query.clone());

                    let now = SystemTime::now();
                    if now >= time_limit {
                        return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                    }

                    if !res.is_empty() {
                        successful = true;
                        break;
                    }
                }

                if !successful {
                    errors.push(error::FailedCaveat::Block(error::FailedBlockCaveat {
                        block_id: i as u32,
                        caveat_id: j as u32,
                        rule: self.symbols.print_caveat(caveat),
                    }));
                }
            }
        }

        if !errors.is_empty() {
            Err(error::Token::FailedLogic(error::Logic::FailedCaveats(
                errors,
            )))
        } else {
            Ok(())
        }
    }

    pub fn print_world(&self) -> String {
        let mut facts = self.world
            .facts
            .iter()
            .map(|f| self.symbols.print_fact(f))
            .collect::<Vec<_>>();
        facts.sort();

        let mut rules = self.world
            .rules
            .iter()
            .map(|r| self.symbols.print_rule(r))
            .collect::<Vec<_>>();
        rules.sort();

        let mut caveats = Vec::new();
        for (index, caveat) in self.caveats.iter().enumerate() {
            caveats.push(format!("Verifier[{}]: {}", index, caveat));
        }

        for (i, block_caveats) in self.token_caveats.iter().enumerate() {
            for (j, caveat) in block_caveats.iter().enumerate() {
                caveats.push(format!("Block[{}][{}]: {}", i, j, self.symbols.print_caveat(caveat)));
            }
        }

        format!("World {{\n  facts: {:#?}\n  rules: {:#?}\n  caveats: {:#?}\n}}", facts, rules, caveats)
    }

    pub fn dump(&self) -> (Vec<Fact>, Vec<Rule>, Vec<Caveat>) {
        let mut caveats = self.caveats.clone();
        caveats.extend(self.token_caveats.iter().flatten().map(|c| Caveat::convert_from(c, &self.symbols)));

        (self.world.facts.iter().map(|f| Fact::convert_from(f, &self.symbols)).collect(),
         self.world.rules.iter().map(|r| Rule::convert_from(r, &self.symbols)).collect(),
         caveats
        )
    }
}

#[derive(Debug,Clone)]
pub struct VerifierLimits {
    pub max_facts: u32,
    pub max_iterations: u32,
    pub max_time: Duration,
}

impl Default for VerifierLimits {
    fn default() -> Self {
        VerifierLimits {
            max_facts: 1000,
            max_iterations: 100,
            max_time: Duration::from_millis(1),
        }
    }
}

impl std::convert::From<VerifierLimits> for crate::datalog::RunLimits {
    fn from(limits: VerifierLimits) -> Self {
        crate::datalog::RunLimits {
            max_facts: limits.max_facts,
            max_iterations: limits.max_iterations,
            max_time: limits.max_time,
        }

    }
}
