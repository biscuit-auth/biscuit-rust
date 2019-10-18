use crate::token::builder::{BlockBuilder};
use crate::datalog::SymbolTable;
use crate::token::*;
use crate::error;
use crate::crypto::KeyPair;
use wasm_bindgen::prelude::*;
use rand::rngs::OsRng;

use super::wasm::builder::*;

pub mod builder;
pub mod crypto;
pub mod verifier;

#[wasm_bindgen]
pub struct SymbolTableBind(SymbolTable);

#[wasm_bindgen]
pub fn default_symbol_table() -> SymbolTableBind {
    let mut syms = SymbolTable::new();
    syms.insert("authority");
    syms.insert("ambient");
    syms.insert("resource");
    syms.insert("operation");
    syms.insert("right");
    syms.insert("current_time");
    syms.insert("revocation_id");

    SymbolTableBind(syms)
}

#[wasm_bindgen]
pub struct BlockBind(Block);

#[wasm_bindgen]
impl BlockBind {
    #[wasm_bindgen(constructor)]
    pub fn new(index: u32, symbols: SymbolTableBind) -> BlockBind {
        BlockBind(Block {
            index,
            symbols: symbols.0,
            facts: vec![],
            caveats: vec![],
        })
    }

    #[wasm_bindgen]
    pub fn symbol_add(&mut self, s: &str) {
        self.0.symbols.add(s);
    }

    #[wasm_bindgen]
    pub fn symbol_insert(&mut self, s: &str) -> u64 {
        self.0.symbols.insert(s)
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct BlockBuilderBind(BlockBuilder);

#[wasm_bindgen]
impl BlockBuilderBind {
    #[wasm_bindgen(constructor)]
    pub fn new(index: u32, symbols: JsValue) -> Self {
        let symbols = symbols.into_serde().expect("Can't format symbols table");
        Self(BlockBuilder::new(index, symbols))
    }

    #[wasm_bindgen()]
    pub fn new_with_default_symbols() -> Self {
        Self(BlockBuilder::new(0, default_symbol_table().0))
    }

    pub fn add_fact(&mut self, fact: FactBind) {
        let f = fact.convert(&mut self.0.symbols);
        self.0.facts.push(f);
    }

    #[wasm_bindgen]
    pub fn add_caveat(&mut self, caveat: RuleBind) {
        let c = caveat.get_inner_rule().convert(&mut self.0.symbols);
        self.0.caveats.push(c);
    }

    #[wasm_bindgen]
    pub fn build(mut self) -> BlockBind {
        let new_syms = self.0.symbols.symbols.split_off(self.0.symbols_start);

        self.0.symbols.symbols = new_syms;

        BlockBind(Block {
            index: self.0.index,
            symbols: self.0.symbols,
            facts: self.0.facts,
            caveats: self.0.caveats,
        })
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct BiscuitBinder(Biscuit);

#[wasm_bindgen]
impl BiscuitBinder {
    #[wasm_bindgen(constructor)]
    pub fn  new(root: &KeyPair, block: BlockBind) -> Result<BiscuitBinder, JsValue> {
        let mut rng = OsRng::new().expect("can't create OS rng");

        Biscuit::new(&mut rng, root, block.0)
            .map_err(|e| JsValue::from_serde(&e).expect("error serde"))
            .map(|biscuit| BiscuitBinder(biscuit))
    }


    pub fn from_biscuit(biscuit: &Biscuit) -> Self {
        BiscuitBinder(biscuit.clone())
    }

    #[wasm_bindgen]
    pub fn from(slice: &[u8]) -> Result<BiscuitBinder, JsValue> {
        Biscuit::from(slice)
            .map_err(|e| JsValue::from_serde(&e).expect("biscuit from error"))
            .map(|biscuit| BiscuitBinder(biscuit))
    }

    #[wasm_bindgen]
    pub fn from_sealed(slice: &[u8], secret: &[u8]) -> Result<BiscuitBinder, JsValue> {
        Biscuit::from_sealed(slice, secret)
            .map_err(|e| JsValue::from_serde(&e).expect("biscuit from error"))
            .map(|biscuit| BiscuitBinder(biscuit))
    }

    #[wasm_bindgen]
    pub fn to_vec(&self) -> Result<Vec<u8>, JsValue> {
        match self.0.clone().get_container().as_ref() {
            None => Err(JsValue::from_serde(&error::Token::InternalError).unwrap()),
            Some(c) => c.to_vec().map_err(|e| JsValue::from_serde(&e).unwrap()),
        }
    }

    #[wasm_bindgen]
    pub fn create_block(&self) -> BlockBuilderBind {
        BlockBuilderBind(BlockBuilder::new((1 + self.0.blocks().len()) as u32, self.0.symbols().clone()))
    }

    #[wasm_bindgen]
    pub fn append(
        &self,
        keypair: KeyPair,
        block: BlockBind,
    ) -> Result<BiscuitBinder, JsValue> {
        let mut rng = OsRng::new().expect("can't create OS rng");
        self.0.append(&mut rng, &keypair, block.0)
            .map_err(|e| JsValue::from_serde(&e).expect("error append"))
            .map(|biscuit| BiscuitBinder(biscuit))
    }
}