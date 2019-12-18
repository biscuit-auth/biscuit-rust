use super::builder::{
    constrained_rule, date, fact, pred, s, string, Atom, Constraint, ConstraintKind, Fact,
    IntConstraint, Rule,
};
use super::Biscuit;
use crate::datalog;
use crate::error;
use std::{collections::HashMap, convert::TryInto, time::SystemTime};

pub struct Verifier<'a> {
    token: &'a Biscuit,
    world: datalog::World,
    facts: Vec<Fact>,
    rules: Vec<Rule>,
    caveats: Vec<Rule>,
    queries: HashMap<String, Rule>,
}

impl<'a> Verifier<'a> {
    pub(crate) fn new(token: &'a Biscuit) -> Result<Self, error::Logic> {
        let world = token.generate_world(&token.symbols)?;
        Ok(Verifier {
            token,
            world,
            facts: vec![],
            rules: vec![],
            caveats: vec![],
            queries: HashMap::new(),
        })
    }

    pub fn reset(&mut self) {
        self.facts.clear();
        self.rules.clear();
        self.caveats.clear();
        self.queries.clear();
    }

    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token> {
        let fact = fact.try_into().map_err(|_| error::Token::ParseError)?;
        self.facts.push(fact);
        Ok(())
    }

    pub fn add_rule<R: TryInto<Rule>>(&mut self, rule: R) -> Result<(), error::Token> {
        let rule = rule.try_into().map_err(|_| error::Token::ParseError)?;
        self.rules.push(rule);
        Ok(())
    }

    pub fn add_query<S: Into<String>, R: TryInto<Rule>>(&mut self, name: S, rule: R) -> Result<(), error::Token> {
        let rule = rule.try_into().map_err(|_| error::Token::ParseError)?;
        self.queries.insert(name.into(), rule);
        Ok(())
    }

    /// verifier caveats
    pub fn add_caveat<R: TryInto<Rule>>(&mut self, caveat: R) -> Result<(), error::Token> {
        let caveat = caveat.try_into().map_err(|_| error::Token::ParseError)?;
        self.caveats.push(caveat);
        Ok(())
    }

    pub fn add_resource(&mut self, resource: &str) {
        self.facts
            .push(fact("resource", &[s("ambient"), string(resource)]));
    }

    pub fn add_operation(&mut self, operation: &str) {
        self.facts
            .push(fact("operation", &[s("ambient"), s(operation)]));
    }

    pub fn set_time(&mut self) {
        self.facts.retain(|f| f.0.name != "time");

        self.facts
            .push(fact("time", &[s("ambient"), date(&SystemTime::now())]));
    }

    pub fn revocation_check(&mut self, ids: &[i64]) {
        let caveat = constrained_rule(
            "revocation_check",
            &[Atom::Variable(0)],
            &[pred("revocation_id", &[Atom::Variable(0)])],
            &[Constraint {
                id: 0,
                kind: ConstraintKind::Integer(IntConstraint::NotIn(ids.iter().cloned().collect())),
            }],
        );
        let _ = self.add_caveat(caveat);
    }

    pub fn verify(&self) -> Result<HashMap<String, Vec<Fact>>, error::Token> {
        let mut symbols = self.token.symbols.clone();

        //FIXME: should check for the presence of any other symbol in the token
        if symbols.get("authority").is_none() || symbols.get("ambient").is_none() {
            return Err(error::Token::MissingSymbols);
        }

        let mut world = self.world.clone();

        let mut queries = HashMap::new();

        for fact in self.facts.iter() {
            world.facts.insert(fact.convert(&mut symbols));
        }

        for rule in self.rules.iter() {
            world.rules.push(rule.convert(&mut symbols));
        }

        let mut errors = vec![];
        for (i, caveat) in self.caveats.iter().enumerate() {
            let c = caveat.convert(&mut symbols);
            let res = world.query_rule(c.clone());
            if res.is_empty() {
                errors.push(error::FailedCaveat::Verifier(error::FailedVerifierCaveat {
                    block_id: 0,
                    caveat_id: i as u32,
                    rule: symbols.print_rule(&c),
                }));
            }
        }

        for (i, block_caveats) in self.token.caveats().iter().enumerate() {
            for (j, caveat) in block_caveats.iter().enumerate() {
                println!("adding caveat to verifier: ({},{}) {:?}", i, j, caveat);
                let res = world.query_rule(caveat.clone());
                if res.is_empty() {
                    errors.push(error::FailedCaveat::Block(error::FailedBlockCaveat {
                        block_id: i as u32,
                        caveat_id: j as u32,
                        rule: symbols.print_rule(caveat),
                    }));
                }
            }
        }

        if !errors.is_empty() {
            return Err(error::Token::FailedLogic(error::Logic::FailedCaveats(
                errors,
            )));
        }

        for (key, query) in self.queries.iter() {
            queries.insert(key.clone(), query.convert(&mut symbols));
        }

        let mut query_results = HashMap::new();
        for (name, rule) in queries.iter() {
            let res = world.query_rule(rule.clone());
            query_results.insert(name.clone(), res);
        }

        Ok(query_results
            .drain()
            .map(|(name, mut facts)| {
                (
                    name,
                    facts
                        .drain(..)
                        .map(|f| Fact::convert_from(&f, &symbols))
                        .collect(),
                )
            })
            .collect())
    }
}
