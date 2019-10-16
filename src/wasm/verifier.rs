use super::builder::*;
use super::BiscuitBinder;
use crate::token::builder::*;
use crate::datalog::{Constraint, ConstraintKind, IntConstraint};

use std::time::SystemTime;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct VerifierBind {
    facts: Vec<Fact>,
    rules: Vec<Rule>,
    caveats: Vec<Rule>,
}

#[wasm_bindgen]
impl VerifierBind {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        VerifierBind{
            facts: vec![],
            rules: vec![],
            caveats: vec![],
        }
    }

    #[wasm_bindgen]
    pub fn add_fact(&mut self, fact: FactBind) {
        self.facts.push(fact.into());
    }

    #[wasm_bindgen]
    pub fn add_rule(&mut self, rule_bind: RuleBind) {
        self.rules.push(rule_bind.get_inner_rule());
    }

    #[wasm_bindgen]
    pub fn add_caveat(&mut self, caveat: RuleBind) {
        self.caveats.push(caveat.get_inner_rule());
    }

    #[wasm_bindgen]
    pub fn add_resource(&mut self, resource: &str) {
        self.facts
            .push(fact("resource", &[s("ambient"), string(resource)]));
    }


    #[wasm_bindgen]
    pub fn add_operation(&mut self, operation: &str) {
        self.facts
            .push(fact("operation", &[s("ambient"), s(operation)]));
    }

    #[wasm_bindgen]
    pub fn set_time(&mut self) {
        self.facts.retain(|f| f.0.name != "time");

        self.facts
            .push(fact("time", &[s("ambient"), date(&SystemTime::now())]));
    }

    #[wasm_bindgen]
    pub fn revocation_check(&mut self, ids: &[i64]) {
        let caveat = constrained_rule(
            "revocation_check",
            &[Atom::Variable(0)],
            &[pred("revocation_id", &[Atom::Variable(0)])],
            &[Constraint {
                id: 0,
                kind: ConstraintKind::Int(IntConstraint::NotIn(ids.iter().cloned().collect())),
            }],
        );
        self.add_caveat(RuleBind::from(caveat));
    }

    #[wasm_bindgen]
    pub fn verify(&self, biscuit: BiscuitBinder) -> Result<(), JsValue> {
        let mut symbols = biscuit.0.symbols().clone();

        let mut ambient_facts = vec![];
        let mut ambient_rules = vec![];
        let mut ambient_caveats = vec![];

        for fact in self.facts.iter() {
            ambient_facts.push(fact.convert(&mut symbols));
        }

        for rule in self.rules.iter() {
            ambient_rules.push(rule.convert(&mut symbols));
        }

        for caveat in self.caveats.iter() {
            ambient_caveats.push(caveat.convert(&mut symbols));
        }

        biscuit.0.check(&symbols, ambient_facts, ambient_rules, ambient_caveats)
            .map_err(|e| JsValue::from_serde(&e).expect("error serde"))
    }
}