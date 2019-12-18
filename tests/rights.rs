#![allow(unused_must_use)]
use biscuit_auth as biscuit;
use biscuit::crypto::KeyPair;
use biscuit::token::builder::*;
use biscuit::token::*;

use rand::{SeedableRng, prelude::StdRng};

fn main() {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let root = KeyPair::new(&mut rng);

    let mut builder = Biscuit::builder(&mut rng, &root);

    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));
    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file2"), s("read")],
    ));
    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("write")],
    ));

    let biscuit1 = builder.build().unwrap();
    println!("{}", biscuit1.print());

    let mut v = biscuit1.verify(root.public()).expect("omg verifier");
    //v.add_resource("file2");
    //v.add_operation("read");
    //v.add_operation("write");

    v.add_caveat(rule(
        "right",
        &[s("right")],
        &[pred(
            "right",
            &[s("authority"), string("file2"), s("write")],
        )],
    ));

    let res = v.verify();
    println!("{:#?}", res);
    panic!()
}
