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
    base_world: datalog::World,
    world: datalog::World,
    caveats: Vec<Rule>,
    queries: HashMap<String, Rule>,
}

impl<'a> Verifier<'a> {
    pub(crate) fn new(token: &'a Biscuit) -> Result<Self, error::Logic> {
        let base_world = token.generate_world(&token.symbols)?;
        let world = base_world.clone();
        Ok(Verifier {
            token,
            base_world,
            world,
            caveats: vec![],
            queries: HashMap::new(),
        })
    }

    pub fn reset(&mut self) {
        self.caveats.clear();
        self.queries.clear();
        self.world = self.base_world.clone();
    }

    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token> {
        let fact = fact.try_into().map_err(|_| error::Token::ParseError)?;
        let mut symbols = self.token.symbols.clone();
        self.world.facts.insert(fact.convert(&mut symbols));
        Ok(())
    }

    pub fn add_rule<R: TryInto<Rule>>(&mut self, rule: R) -> Result<(), error::Token> {
        let rule = rule.try_into().map_err(|_| error::Token::ParseError)?;
        let mut symbols = self.token.symbols.clone();
        self.world.rules.push(rule.convert(&mut symbols));
        Ok(())
    }

    pub fn add_query<S: Into<String>, R: TryInto<Rule>>(
        &mut self,
        name: S,
        rule: R,
    ) -> Result<(), error::Token> {
        let rule = rule.try_into().map_err(|_| error::Token::ParseError)?;
        self.queries.insert(name.into(), rule);
        Ok(())
    }

    pub fn query<R: TryInto<Rule>>(
        &mut self,
        rule: R,
    ) -> Result<Vec<Fact>, error::Token> {
        let rule = rule.try_into().map_err(|_| error::Token::ParseError)?;
        let mut symbols = self.token.symbols.clone();
        self.world.run();
        let mut res = self.world.query_rule(rule.convert(&mut symbols));

        Ok(res
           .drain(..)
           .map(|f| Fact::convert_from(&f, &symbols))
           .collect())
    }

    /// verifier caveats
    pub fn add_caveat<R: TryInto<Rule>>(&mut self, caveat: R) -> Result<(), error::Token> {
        let caveat = caveat.try_into().map_err(|_| error::Token::ParseError)?;
        self.caveats.push(caveat);
        Ok(())
    }

    pub fn add_resource(&mut self, resource: &str) {
        let fact = fact("resource", &[s("ambient"), string(resource)]);
        let mut symbols = self.token.symbols.clone();
        self.world.facts.insert(fact.convert(&mut symbols));
    }

    pub fn add_operation(&mut self, operation: &str) {
        let fact = fact("operation", &[s("ambient"), s(operation)]);
        let mut symbols = self.token.symbols.clone();
        self.world.facts.insert(fact.convert(&mut symbols));
    }

    pub fn set_time(&mut self) {
        let fact = fact("time", &[s("ambient"), date(&SystemTime::now())]);
        let mut symbols = self.token.symbols.clone();
        self.world.facts.insert(fact.convert(&mut symbols));
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

    pub fn verify(&mut self) -> Result<HashMap<String, Vec<Fact>>, error::Token> {
        let mut symbols = self.token.symbols.clone();

        //FIXME: should check for the presence of any other symbol in the token
        if symbols.get("authority").is_none() || symbols.get("ambient").is_none() {
            return Err(error::Token::MissingSymbols);
        }

        self.world.run();

        let mut queries = HashMap::new();

        let mut errors = vec![];
        for (i, caveat) in self.caveats.iter().enumerate() {
            let c = caveat.convert(&mut symbols);
            let res = self.world.query_rule(c.clone());
            if res.is_empty() {
                errors.push(error::FailedCaveat::Verifier(error::FailedVerifierCaveat {
                    caveat_id: i as u32,
                    rule: symbols.print_rule(&c),
                }));
            }
        }

        for (i, block_caveats) in self.token.caveats().iter().enumerate() {
            for (j, caveat) in block_caveats.iter().enumerate() {
                println!("adding caveat to verifier: ({},{}) {:?}", i, j, caveat);
                let res = self.world.query_rule(caveat.clone());
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
            let res = self.world.query_rule(rule.clone());
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
