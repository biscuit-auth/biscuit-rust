#![allow(unused_must_use)]
use biscuit::builder::*;
use biscuit::datalog::SymbolTable;
use biscuit::KeyPair;
use biscuit::*;
use biscuit_auth as biscuit;

use rand::{prelude::StdRng, SeedableRng};

fn main() {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

    let mut builder = Biscuit::builder();

    builder.add_fact(fact(
        "right",
        &[string("authority"), string("file1"), string("read")],
    ));
    builder.add_fact(fact(
        "right",
        &[string("authority"), string("file2"), string("read")],
    ));
    builder.add_fact(fact(
        "right",
        &[string("authority"), string("file1"), string("write")],
    ));

    let biscuit1 = builder
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    println!("{}", biscuit1);

    let mut v = biscuit1.authorizer().expect("omg verifier");
    //v.add_resource("file2");
    //v.add_operation("read");
    //v.add_operation("write");

    v.add_check(rule(
        "right",
        &[string("right")],
        &[pred(
            "right",
            &[string("authority"), string("file2"), string("write")],
        )],
    ));

    let res = v.authorize();
    println!("{:#?}", res);
    panic!()
}
