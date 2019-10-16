use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

use biscuit::*;

#[wasm_bindgen(module = "tests/wasm_test.js")]
extern "C" {
    fn create_biscuit_with_fact_and_verify_it();
}

#[wasm_bindgen_test]
fn wasm_create_biscuit_with_authority_fact_and_verify() {
    create_biscuit_with_fact_and_verify_it();
}