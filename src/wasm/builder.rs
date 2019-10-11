//use::crate::token::{Biscuit, Block, BlockBind};
use crate::token::builder::*;
use crate::token::{Biscuit, Block};
use crate::token::default_symbol_table;
use crate::crypto::KeyPair;
use crate::datalog::{self, SymbolTable};
use wasm_bindgen::prelude::*;
use rand::rngs::OsRng;

#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct AtomBind {
    atom: Atom,
}

#[wasm_bindgen]
pub struct FactBind(Predicate);

impl FactBind {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Fact {
        datalog::Fact {
            predicate: self.0.convert(symbols),
        }
    }
}

impl Into<Fact> for FactBind {
    fn into(self) -> Fact {
        Fact::from(self.0)
    }
}

#[wasm_bindgen]
pub fn fact_bind(name: &str, ids: JsValue) -> FactBind {
    let ids: Vec<Atom> = ids.into_serde().expect("incorrect atom vec");
    FactBind(pred(name, &ids))
}

#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RuleBind{
    rule: Rule
}

impl RuleBind {
    pub fn get_inner_rule(self) -> Rule {
        self.rule
    }
}

impl From<Rule> for RuleBind {
    fn from(rule: Rule) -> Self {
        Self{ rule }
    }
}

#[wasm_bindgen]
pub fn rule_bind(
    head_name: &str,
    head_ids: JsValue,
    predicates: JsValue,
) -> RuleBind {
    let head_ids: Vec<Atom> = head_ids.into_serde().unwrap();
    let predicates: Vec<Predicate> = predicates.into_serde().unwrap();
    RuleBind {
        rule: rule(head_name, head_ids.as_slice(), &predicates),
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
    pub fn new(base_symbols: JsValue) -> Self {
        let base_symbols: SymbolTable = base_symbols.into_serde().expect("bad symbols table format");
        Self {
            symbols_start: base_symbols.symbols.len(),
            symbols: base_symbols,
            facts: vec![],
            rules: vec![],
        }
    }

    #[wasm_bindgen()]
    pub fn new_with_default_symbol() -> Self {
        let symbols = default_symbol_table();
        Self {
            symbols_start: symbols.symbols.len(),
            symbols,
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

    #[wasm_bindgen]
    pub fn add_right(&mut self, resource: &str, right: &str) {
        self.add_authority_fact(FactBind(Predicate{
            name: "right".to_string(),
            ids: vec![s("authority"), string(resource), s(right)],
        }));
    }

    #[wasm_bindgen]
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

