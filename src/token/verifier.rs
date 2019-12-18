use super::builder::{constrained_rule, date, fact, pred, s, string, Atom, Fact, Rule, Constraint, ConstraintKind, IntConstraint};
use super::Biscuit;
use crate::error;
use std::{convert::TryInto, time::SystemTime, collections::HashMap};

pub struct Verifier<'a> {
    token: &'a Biscuit,
    facts: Vec<Fact>,
    rules: Vec<Rule>,
    caveats: Vec<Rule>,
    queries: HashMap<String, Rule>,
}

impl<'a> Verifier<'a> {
    pub(crate) fn new(token: &'a Biscuit) -> Self {
        Verifier {
            token,
            facts: vec![],
            rules: vec![],
            caveats: vec![],
            queries: HashMap::new(),
        }
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

        //FIXME: should check for the presence of any other symbol ion the token
        if symbols.get("authority").is_none() || symbols.get("ambient").is_none() {
          return Err(error::Token::MissingSymbols);
        }

        let mut ambient_facts = vec![];
        let mut ambient_rules = vec![];
        let mut caveats = vec![];
        let mut queries = HashMap::new();

        for fact in self.facts.iter() {
            ambient_facts.push(fact.convert(&mut symbols));
        }

        for rule in self.rules.iter() {
            ambient_rules.push(rule.convert(&mut symbols));
        }

        for caveat in self.caveats.iter() {
            caveats.push(caveat.convert(&mut symbols));
        }

        for (key, query) in self.queries.iter() {
            queries.insert(key.clone(), query.convert(&mut symbols));
        }

        self.token.check(
            &symbols,
            ambient_facts,
            ambient_rules,
            caveats,
            queries,
        ).map_err(error::Token::FailedLogic)
         .map(|mut query_results| {
           query_results.drain().map(|(name, mut facts)| {
             (
               name,
               facts.drain(..).map(|f| Fact::convert_from(&f, &symbols)).collect()
             )
           }).collect()
         })
    }
}
