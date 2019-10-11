use crate::token::builder::BlockBuilder;
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
pub struct BlockBind(Block);

#[wasm_bindgen]
impl BlockBind {
    #[wasm_bindgen(constructor)]
    pub fn new(index: u32, symbols: JsValue) -> BlockBind {
        let symbols = symbols.into_serde().expect("malformated symbols");
        BlockBind(Block {
            index,
            symbols,
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