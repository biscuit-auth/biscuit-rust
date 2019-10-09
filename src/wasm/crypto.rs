use crate::crypto::KeyPair;

use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;


#[wasm_bindgen]
pub fn keypair_new() -> KeyPair {
    let mut rng = OsRng::new().unwrap();
    KeyPair::new(&mut rng)
}