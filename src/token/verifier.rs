use super::builder::{constrained_rule, date, fact, pred, s, string, Atom, Fact, Rule, Constraint, ConstraintKind, IntConstraint};
use super::Biscuit;
use crate::{error, parser};
use std::{time::SystemTime, collections::HashMap};

pub struct Verifier<'a> {
    token: &'a Biscuit,
    facts: Vec<Fact>,
    rules: Vec<Rule>,
    block_caveats: Vec<Rule>,
    authority_caveats: Vec<Rule>,
    queries: HashMap<String, Rule>,
}

impl<'a> Verifier<'a> {
    pub(crate) fn new(token: &'a Biscuit) -> Self {
        Verifier {
            token,
            facts: vec![],
            rules: vec![],
            block_caveats: vec![],
            authority_caveats: vec![],
            queries: HashMap::new(),
        }
    }

    pub fn add_fact(&mut self, fact: Fact) {
        self.facts.push(fact);
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn add_query<S: Into<String>>(&mut self, name: S, rule: Rule) {
        self.queries.insert(name.into(), rule);
    }

    pub fn add_fact_str(&mut self, f: &str) -> bool {
        if let Ok((_, f)) = parser::fact(f) {
            self.facts.push(f);
            true
        } else {
            false
        }
    }

    pub fn add_rule_str(&mut self, r: &str) -> bool {
        if let Ok((_, r)) = parser::rule(r) {
            self.rules.push(r);
            true
        } else {
            false
        }
    }

    /// block level caveats
    ///
    /// these caveats will be tested on each block
    pub fn add_block_caveat(&mut self, caveat: Rule) {
        self.block_caveats.push(caveat);
    }

    pub fn add_block_caveat_str(&mut self, r: &str) -> bool {
        if let Ok((_, r)) = parser::rule(r) {
            self.block_caveats.push(r);
            true
        } else {
            false
        }
    }

    /// caveats for authority level data
    ///
    /// these caveats will be tested once for the entire token
    pub fn add_authority_caveat(&mut self, caveat: Rule) {
        self.authority_caveats.push(caveat);
    }

    pub fn add_authority_caveat_str(&mut self, r: &str) -> bool {
        if let Ok((_, r)) = parser::rule(r) {
            self.authority_caveats.push(r);
            true
        } else {
            false
        }
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
        self.add_block_caveat(caveat);
    }

    pub fn verify(&self) -> Result<HashMap<String, HashMap<u32, Vec<Fact>>>, error::Token> {
        let mut symbols = self.token.symbols.clone();

        //FIXME: should check for the presence of any other symbol ion the token
        if symbols.get("authority").is_none() || symbols.get("ambient").is_none() {
          return Err(error::Token::MissingSymbols);
        }

        let mut ambient_facts = vec![];
        let mut ambient_rules = vec![];
        let mut authority_caveats = vec![];
        let mut block_caveats = vec![];
        let mut queries = HashMap::new();

        for fact in self.facts.iter() {
            ambient_facts.push(fact.convert(&mut symbols));
        }

        for rule in self.rules.iter() {
            ambient_rules.push(rule.convert(&mut symbols));
        }

        for caveat in self.authority_caveats.iter() {
            authority_caveats.push(caveat.convert(&mut symbols));
        }

        for caveat in self.block_caveats.iter() {
            block_caveats.push(caveat.convert(&mut symbols));
        }

        for (key, query) in self.queries.iter() {
            queries.insert(key.clone(), query.convert(&mut symbols));
        }

        self.token.check(
            &symbols,
            ambient_facts,
            ambient_rules,
            authority_caveats,
            block_caveats,
            queries,
        ).map_err(error::Token::FailedLogic)
         .map(|mut query_results| {
           query_results.drain().map(|(name, mut result)| {
             (
               name,
               result.drain().map(|(block_id, mut facts)| {
                 (block_id, facts.drain(..).map(|f| Fact::convert_from(&f, &symbols)).collect())
               }).collect()
             )
           }).collect()
         })
    }
}
