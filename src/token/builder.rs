use super::{Biscuit, Block};
use crate::crypto::KeyPair;
use crate::datalog::{
    self, Constraint, ConstraintKind, DateConstraint, StrConstraint, SymbolTable, ID,
};
use crate::error;
use rand_core::{CryptoRng, RngCore};
use rand::rngs::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};
use wasm_bindgen::prelude::*;

#[derive(Clone, Debug)]
pub struct BlockBuilder {
    pub index: u32,
    pub symbols_start: usize,
    pub symbols: SymbolTable,
    pub facts: Vec<datalog::Fact>,
    pub rules: Vec<datalog::Rule>,
    pub caveats: Vec<datalog::Rule>,
}

impl BlockBuilder {
    pub fn new(index: u32, base_symbols: SymbolTable) -> BlockBuilder {
        BlockBuilder {
            index,
            symbols_start: base_symbols.symbols.len(),
            symbols: base_symbols,
            facts: vec![],
            rules: vec![],
            caveats: vec![],
        }
    }

    pub fn add_fact(&mut self, fact: &Fact) {
        let f = fact.convert(&mut self.symbols);
        self.facts.push(f);
    }

    pub fn add_rule(&mut self, rule: &Rule) {
        let c = rule.convert(&mut self.symbols);
        self.rules.push(c);
    }

    pub fn add_caveat(&mut self, caveat: &Rule) {
        let c = caveat.convert(&mut self.symbols);
        self.caveats.push(c);
    }

    pub fn build(mut self) -> Block {
        let new_syms = self.symbols.symbols.split_off(self.symbols_start);

        self.symbols.symbols = new_syms;

        Block {
            index: self.index,
            symbols: self.symbols,
            facts: self.facts,
            rules: self.rules,
            caveats: self.caveats,
        }
    }

    pub fn check_right(&mut self, right: &str) {
        let caveat = rule(
            "check_right",
            &[s(right)],
            &[
                pred("resource", &[s("ambient"), Atom::Variable(0)]),
                pred("operation", &[s("ambient"), s(right)]),
                pred("right", &[s("authority"), Atom::Variable(0), s(right)]),
            ],
        );

        self.add_caveat(&caveat);
    }

    pub fn check_resource(&mut self, resource: &str) {
        let caveat = rule(
            "resource_check",
            &[s("resource_check")],
            &[pred("resource", &[s("ambient"), string(resource)])],
        );

        self.add_caveat(&caveat);
    }

    pub fn check_operation(&mut self, operation: &str) {
        let caveat = rule(
            "operation_check",
            &[s("operation_check")],
            &[pred("operation", &[s("ambient"), s(operation)])],
        );

        self.add_caveat(&caveat);
    }

    pub fn resource_prefix(&mut self, prefix: &str) {
        let caveat = constrained_rule(
            "prefix",
            &[Atom::Variable(0)],
            &[pred("resource", &[s("ambient"), Atom::Variable(0)])],
            &[Constraint {
                id: 0,
                kind: ConstraintKind::Str(StrConstraint::Prefix(prefix.to_string())),
            }],
        );

        self.add_caveat(&caveat);
    }

    pub fn resource_suffix(&mut self, suffix: &str) {
        let caveat = constrained_rule(
            "suffix",
            &[Atom::Variable(0)],
            &[pred("resource", &[s("ambient"), Atom::Variable(0)])],
            &[Constraint {
                id: 0,
                kind: ConstraintKind::Str(StrConstraint::Suffix(suffix.to_string())),
            }],
        );

        self.add_caveat(&caveat);
    }

    pub fn expiration_date(&mut self, date: SystemTime) {
        let dur = date.duration_since(UNIX_EPOCH).unwrap();
        let d = dur.as_secs();

        let caveat = constrained_rule(
            "expiration",
            &[Atom::Variable(0)],
            &[pred("time", &[s("ambient"), Atom::Variable(0)])],
            &[Constraint {
                id: 0,
                kind: ConstraintKind::Date(DateConstraint::Before(d)),
            }],
        );

        self.add_caveat(&caveat);
    }

    pub fn revocation_id(&mut self, id: i64) {
        self.add_fact(&fact("revocation_id", &[int(id)]));
    }
}


#[wasm_bindgen]
pub struct BiscuitBuilderBind {
    symbols_start: usize,
    symbols: SymbolTable,
    facts: Vec<datalog::Fact>,
    rules: Vec<datalog::Rule>,
}

#[wasm_bindgen]
impl BiscuitBuilderBind {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            symbols_start: 0,
            symbols: SymbolTable::new(),
            facts: vec![],
            rules: vec![],
        }
    }

    #[wasm_bindgen]
    pub fn add_authority_fact(&mut self, mut fact: FactBind) {
        let authority_symbol = Atom::Symbol("authority".to_string());
        if fact.0.ids.is_empty() || fact.0.ids[0] != authority_symbol {
            fact.0.ids.insert(0, authority_symbol);
        }

        let f = fact.convert(&mut self.symbols);
        self.facts.push(f);
    }

    #[wasm_bindgen]
    pub fn add_authority_rule(&mut self, mut rule_bind: RuleBind) {
        let authority_symbol = Atom::Symbol("authority".to_string());
        if rule_bind.rule.0.ids.is_empty() || rule_bind.rule.0.ids[0] != authority_symbol {
            rule_bind.rule.0.ids.insert(0, authority_symbol);
        }

        let r = rule_bind.rule.convert(&mut self.symbols);
        self.rules.push(r);
    }

    pub fn add_right(&mut self, resource: &str, right: &str) {
        self.add_authority_fact(FactBind(Predicate{
            name: "right".to_string(),
            ids: vec![s("authority"), string(resource), s(right)],
        }));
    }

    pub fn build(mut self,root: KeyPair) -> Result<Biscuit, JsValue> {
        let mut rng = OsRng::new().expect("os range");
        let new_syms = self.symbols.symbols.split_off(self.symbols_start);

        self.symbols.symbols = new_syms;

        let authority_block = Block {
            index: 0,
            symbols: self.symbols,
            facts: self.facts,
            caveats: self.rules,
        };

        Biscuit::new(&mut rng, &root, authority_block).map_err(|e| JsValue::from_serde(&e).unwrap())
    }
}


pub struct BiscuitBuilder<'a, 'b, R: RngCore + CryptoRng> {
    rng: &'a mut R,
    root: &'b KeyPair,
    pub symbols_start: usize,
    pub symbols: SymbolTable,
    pub facts: Vec<datalog::Fact>,
    pub rules: Vec<datalog::Rule>,
    pub caveats: Vec<datalog::Rule>,
}

impl<'a, 'b, R: RngCore + CryptoRng> BiscuitBuilder<'a, 'b, R> {
    pub fn new(
        rng: &'a mut R,
        root: &'b KeyPair,
        base_symbols: SymbolTable,
    ) -> BiscuitBuilder<'a, 'b, R> {
        BiscuitBuilder {
            rng,
            root,
            symbols_start: base_symbols.symbols.len(),
            symbols: base_symbols,
            facts: vec![],
            rules: vec![],
            caveats: vec![],
        }
    }

    pub fn add_authority_fact(&mut self, fact: &Fact) {
        let mut fact = fact.clone();
        let authority_symbol = Atom::Symbol("authority".to_string());
        if fact.0.ids.is_empty() || fact.0.ids[0] != authority_symbol {
            fact.0.ids.insert(0, authority_symbol);
        }

        let f = fact.convert(&mut self.symbols);
        self.facts.push(f);
    }

    pub fn add_authority_rule(&mut self, rule: &Rule) {
        let mut rule = rule.clone();
        let authority_symbol = Atom::Symbol("authority".to_string());
        if rule.0.ids.is_empty() || rule.0.ids[0] != authority_symbol {
            rule.0.ids.insert(0, authority_symbol);
        }

        let r = rule.convert(&mut self.symbols);
        self.rules.push(r);
    }

    pub fn add_authority_caveat(&mut self, caveat: &Rule) {
        let r = caveat.convert(&mut self.symbols);
        self.caveats.push(r);
    }

    pub fn add_right(&mut self, resource: &str, right: &str) {
        self.add_authority_fact(&fact(
            "right",
            &[s("authority"), string(resource), s(right)],
        ));
    }

    pub fn build(mut self) -> Result<Biscuit, error::Token> {
        let new_syms = self.symbols.symbols.split_off(self.symbols_start);

        self.symbols.symbols = new_syms;

        let authority_block = Block {
            index: 0,
            symbols: self.symbols,
            facts: self.facts,
            rules: self.rules,
            caveats: self.caveats,
        };

        Biscuit::new(self.rng, self.root, authority_block)
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct AtomBind {
    atom: Atom,
}

impl From<Atom> for AtomBind {
    fn from(atom: Atom) -> Self {
        AtomBind{atom}
    }
}

impl Into<Atom> for AtomBind {
    fn into(self) -> Atom {
        self.atom
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Atom {
    Symbol(String),
    Variable(u32),
    Integer(i64),
    Str(String),
    Date(u64),
}

impl Atom {
    pub fn convert(&self, symbols: &mut SymbolTable) -> ID {
        match self {
            Atom::Symbol(s) => ID::Symbol(symbols.insert(s)),
            Atom::Variable(i) => ID::Variable(*i),
            Atom::Integer(i) => ID::Integer(*i),
            Atom::Str(s) => ID::Str(s.clone()),
            Atom::Date(d) => ID::Date(*d),
        }
    }
}

impl From<&Atom> for Atom {
    fn from(i: &Atom) -> Self {
        match i {
            Atom::Symbol(ref s) => Atom::Symbol(s.clone()),
            Atom::Variable(ref v) => Atom::Variable(*v),
            Atom::Integer(ref i) => Atom::Integer(*i),
            Atom::Str(ref s) => Atom::Str(s.clone()),
            Atom::Date(ref d) => Atom::Date(*d),
        }
    }
}

impl AsRef<Atom> for Atom {
    fn as_ref(&self) -> &Atom {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Predicate {
    pub name: String,
    pub ids: Vec<Atom>,
}

impl Predicate {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Predicate {
        let name = symbols.insert(&self.name);
        let mut ids = vec![];

        for id in self.ids.iter() {
            ids.push(id.convert(symbols));
        }

        datalog::Predicate { name, ids }
    }
}

impl Predicate {
    pub fn new(name: String, ids: &[Atom]) -> Predicate {
        Predicate {
            name,
            ids: ids.to_vec(),
        }
    }
}

impl AsRef<Predicate> for Predicate {
    fn as_ref(&self) -> &Predicate {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Fact(pub Predicate);

#[wasm_bindgen]
pub struct FactBind(Predicate);

impl FactBind {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Fact {
        datalog::Fact {
            predicate: self.0.convert(symbols),
        }
    }
}

impl Fact {
    pub fn new(name: String, ids: &[Atom]) -> Fact {
        Fact(Predicate::new(name, ids))
    }
}

impl Fact {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Fact {
        datalog::Fact {
            predicate: self.0.convert(symbols),
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq)]
pub struct RuleBind{
    rule: Rule
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule(
    pub Predicate,
    pub Vec<Predicate>,
    pub Vec<datalog::Constraint>,
);

impl Rule {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Rule {
        let head = self.0.convert(symbols);
        let mut body = vec![];
        let mut constraints = vec![];

        for p in self.1.iter() {
            body.push(p.convert(symbols));
        }

        for c in self.2.iter() {
            constraints.push(c.clone());
        }

        datalog::Rule {
            head,
            body,
            constraints,
        }
    }
}

/// creates a new fact
pub fn fact<I: AsRef<Atom>>(name: &str, ids: &[I]) -> Fact {
    Fact(pred(name, ids))
}

/// creates a predicate
pub fn pred<I: AsRef<Atom>>(name: &str, ids: &[I]) -> Predicate {
    Predicate {
        name: name.to_string(),
        ids: ids.iter().map(|id| id.as_ref().clone()).collect(),
    }
}

/// creates a rule
pub fn rule<I: AsRef<Atom>, P: AsRef<Predicate>>(
    head_name: &str,
    head_ids: &[I],
    predicates: &[P],
) -> Rule {
    Rule(
        pred(head_name, head_ids),
        predicates.iter().map(|p| p.as_ref().clone()).collect(),
        Vec::new(),
    )
}

/// creates a rule with constraints
pub fn constrained_rule<I: AsRef<Atom>, P: AsRef<Predicate>, C: AsRef<datalog::Constraint>>(
    head_name: &str,
    head_ids: &[I],
    predicates: &[P],
    constraints: &[C],
) -> Rule {
    Rule(
        pred(head_name, head_ids),
        predicates.iter().map(|p| p.as_ref().clone()).collect(),
        constraints.iter().map(|c| c.as_ref().clone()).collect(),
    )
}

/// creates an integer value
#[wasm_bindgen]
pub fn int_bind(i: i64) -> AtomBind {
    AtomBind::from(Atom::Integer(i))
}

/// creates an integer value
pub fn int(i: i64) -> Atom {
    Atom::Integer(i)
}

/// creates a string
pub fn string(s: &str) -> Atom {
    Atom::Str(s.to_string())
}

#[wasm_bindgen]
pub fn string_bind(s: String) -> AtomBind {
    AtomBind::from(Atom::Str(s))
}

/// creates a symbol
///
/// once the block is generated, this symbol will be added to the symbol table if needed
pub fn s(s: &str) -> Atom {
    Atom::Symbol(s.to_string())
}

#[wasm_bindgen]
pub fn s_bind(s: String) -> AtomBind {
    AtomBind::from(Atom::Symbol(s))
}

/// creates a symbol
///
/// once the block is generated, this symbol will be added to the symbol table if needed
pub fn symbol(s: &str) -> Atom {
    Atom::Symbol(s.to_string())
}

#[wasm_bindgen]
pub fn symbol_bind(s: String) -> AtomBind {
    AtomBind::from(Atom::Symbol(s))
}

/// creates a date
///
/// internally the date will be stored as seconds since UNIX_EPOCH
pub fn date(t: &SystemTime) -> Atom {
    let dur = t.duration_since(UNIX_EPOCH).unwrap();
    Atom::Date(dur.as_secs())
}

/// creates a variable for a rule
pub fn var(i: u32) -> Atom {
    Atom::Variable(i)
}

/// creates a variable for a rule
pub fn variable(i: u32) -> Atom {
    Atom::Variable(i)
}
