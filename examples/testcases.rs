#![allow(unused_must_use)]
extern crate biscuit_auth as biscuit;
extern crate curve25519_dalek;
extern crate hex;
extern crate prost;
extern crate rand;

use biscuit::crypto::KeyPair;
use biscuit::error;
use biscuit::token::{builder::*, Biscuit};
use curve25519_dalek::scalar::Scalar;
use prost::Message;
use rand::prelude::*;
use std::{
  fs::File,
  io::Write,
  time::*,
  collections::BTreeSet
};

fn main() {
    let mut args = std::env::args();
    args.next();
    let target = match args.next() {
        Some(arg) => arg,
        None => {
            println!("missing target directory argument");
            return;
        }
    };

    let test = match args.next().as_deref() {
        Some("--test") => true,
        Some(arg) => {
            println!("unknown argument: {}", arg);
            return;
        }
        None => false,
    };

    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let root = KeyPair::new_with_rng(&mut rng);
    println!("# Biscuit samples and expected results\n");
    println!(
        "root secret key: {}",
        hex::encode(root.private().to_bytes())
    );
    println!("root public key: {}", hex::encode(root.public().to_bytes()));

    println!("\n------------------------------\n");
    basic_token(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    different_root_key(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    invalid_signature_format(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    random_block(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    invalid_signature(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    reordered_blocks(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    invalid_block_fact_authority(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    invalid_block_fact_ambient(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    expired_token(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    authority_rules(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    verifier_authority_checks(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    authority_checks(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    block_rules(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    regex_constraint(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    multi_queries_checks(&mut rng, &target, &root, test);

    println!("\n------------------------------\n");
    check_head_name(&mut rng, &target, &root, test);
}

fn validate_token(
    root: &KeyPair,
    data: &[u8],
    ambient_facts: Vec<Fact>,
    ambient_rules: Vec<Rule>,
    checks: Vec<Vec<Rule>>,
) -> Result<(), error::Token> {
    let token = Biscuit::from(&data[..])?;

    let mut verifier = token.verify(root.public())?;
    for fact in ambient_facts {
        verifier.add_fact(fact);
    }
    for rule in ambient_rules {
        verifier.add_rule(rule);
    }
    for check in checks {
        verifier.add_check(&check[..]);
    }

    println!("verifier world:\n{}", verifier.print_world());
    verifier.verify()?;
    Ok(())
}

fn write_testcase(target: &str, name: &str, data: &[u8]) {
    //println!("written to: {}/{}", target, name);

    let mut file = File::create(&format!("{}/{}.bc", target, name)).unwrap();
    file.write_all(data).unwrap();
    file.flush().unwrap();
}

fn load_testcase(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(&format!("{}/{}.bc", target, name)).unwrap()
}

fn print_diff(actual: &str, expected: &str) {
    if actual != expected {
        println!("{}", colored_diff::PrettyDifference { expected, actual })
    }
}

fn basic_token<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## basic token: test1_basic.bc");

    let mut builder = Biscuit::builder(&root);

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

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[s("ambient"), var("0")]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test1_basic");
        let token = Biscuit::from(&v[..]).unwrap();

        let actual = biscuit2.print();
        let expected = token.print();
        print_diff(&actual, &expected);
        v
    } else {
        println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test1_basic", &data[..]);
        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![]
            )
        );
}

fn different_root_key<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## different root key: test2_different_root_key.bc");

    let root2 = KeyPair::new_with_rng(rng);
    let mut builder = Biscuit::builder(&root2);

    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[s("ambient"), var("0")]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test2_different_root_key");
        v
    } else {
        println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test2_different_root_key", &data[..]);
        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![]
            )
        );
}

fn invalid_signature_format<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## invalid signature format: test3_invalid_signature_format.bc");

    let mut builder = Biscuit::builder(&root);

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

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[s("ambient"), var("0")]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test3_invalid_signature_format");
        v
    } else {
        println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

        let serialized = biscuit2.container().unwrap();
        let mut proto = serialized.to_proto();
        proto.signature.z.truncate(16);
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();
        write_testcase(target, "test3_invalid_signature_format", &data[..]);
        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![]
        )
    );
}

fn random_block<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## random block: test4_random_block.bc");

    let mut builder = Biscuit::builder(&root);

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

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[s("ambient"), var("0")]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test4_random_block");
        v
    } else {
        println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

        let serialized = biscuit2.container().unwrap();
        let mut proto = serialized.to_proto();
        let arr: [u8; 32] = rng.gen();
        proto.blocks[0] = Vec::from(&arr[..]);
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();

        write_testcase(target, "test4_random_block", &data[..]);
        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![]
        )
    );
}

fn invalid_signature<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## invalid signature: test5_invalid_signature.bc");

    let mut builder = Biscuit::builder(&root);

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

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[s("ambient"), var("0")]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test5_invalid_signature");
        v
    } else {
        println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

        let mut serialized = biscuit2.container().unwrap().clone();
        serialized.signature.z = serialized.signature.z + Scalar::one();

        let data = serialized.to_vec().unwrap();
        write_testcase(target, "test5_invalid_signature", &data[..]);

        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![]
        )
    );
}

fn reordered_blocks<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## reordered blocks: test6_reordered_blocks.bc");

    let mut builder = Biscuit::builder(&root);

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

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[s("ambient"), var("0")]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

    let mut block3 = biscuit2.create_block();

    block3.add_check(rule(
        "check2",
        &[var("0")],
        &[pred("resource", &[s("ambient"), string("file1")])],
    ));

    let keypair3 = KeyPair::new_with_rng(rng);
    let biscuit3 = biscuit2.append_with_rng(rng, &keypair3, block3).unwrap();

    let mut serialized = biscuit3.container().unwrap().clone();
    let mut blocks = vec![];
    blocks.push(serialized.blocks[1].clone());
    blocks.push(serialized.blocks[0].clone());
    serialized.blocks = blocks;

    let mut keys = vec![];
    keys.push(serialized.keys[0].clone());
    keys.push(serialized.keys[2].clone());
    keys.push(serialized.keys[1].clone());
    serialized.keys = keys;

    let data = if test {
        let v = load_testcase(target, "test6_reordered_blocks");
        v
    } else {
        let data = serialized.to_vec().unwrap();
        write_testcase(target, "test6_reordered_blocks", &data[..]);
        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![]
        )
    );
}

fn invalid_block_fact_authority<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## invalid block fact with authority tag: test7_invalid_block_fact_authority.bc");

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[pred("operation", &[s("ambient"), s("read")])],
    ));

    block2.add_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("write")],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test7_invalid_block_fact_authority");
        let expected = Biscuit::from(&v[..]).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test7_invalid_block_fact_authority", &data[..]);

        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![]
        )
    );
}

fn invalid_block_fact_ambient<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## invalid block fact with ambient tag: test8_invalid_block_fact_ambient.bc");

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[pred("operation", &[s("ambient"), s("read")])],
    ));

    block2.add_fact(fact("right", &[s("ambient"), string("file1"), s("write")]));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test8_invalid_block_fact_ambient");
        let expected = Biscuit::from(&v[..]).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test8_invalid_block_fact_ambient", &data[..]);
        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![]
        )
    );
}

fn expired_token<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## expired token: test9_expired_token.bc");

    let builder = Biscuit::builder(&root);
    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[string("file1")],
        &[pred("resource", &[s("ambient"), string("file1")])],
    ));
    // January 1 2019
    block2.expiration_date(
        UNIX_EPOCH
            .checked_add(Duration::from_secs(49 * 365 * 24 * 3600))
            .unwrap(),
    );

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test9_expired_token");
        let expected = Biscuit::from(&v[..]).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test9_expired_token", &data[..]);

        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
                fact("operation", &[s("ambient"), s("read")]),
                fact("time", &[s("ambient"), date(&UNIX_EPOCH.checked_add(Duration::from_secs(1608542592)).unwrap())])
            ],
            vec![],
            vec![]
        )
    );
}

fn authority_rules<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## authority rules: test10_authority_rules.bc");

    let mut builder = Biscuit::builder(&root);
    builder.add_authority_rule(rule(
        "right",
        &[symbol("authority"), variable("1"), symbol("read")],
        &[
            pred("resource", &[s("ambient"), variable("1")]),
            pred("owner", &[s("ambient"), variable("0"), variable("1")]),
        ],
    ));
    builder.add_authority_rule(rule(
        "right",
        &[symbol("authority"), variable("1"), symbol("write")],
        &[
            pred("resource", &[s("ambient"), variable("1")]),
            pred("owner", &[s("ambient"), variable("0"), variable("1")]),
        ],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[variable("0"), variable("1")],
        &[
            pred("right", &[s("authority"), var("0"), var("1")]),
            pred("resource", &[s("ambient"), var("0")]),
            pred("operation", &[s("ambient"), var("1")]),
        ],
    ));
    block2.add_check(rule(
        "check2",
        &[variable("0")],
        &[
            pred("resource", &[s("ambient"), var("0")]),
            pred("owner", &[s("ambient"), symbol("alice"), var("0")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test10_authority_rules");
        let expected = Biscuit::from(&v[..]).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test10_authority_rules", &data[..]);
        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
                fact("operation", &[s("ambient"), s("read")]),
                fact("owner", &[s("ambient"), s("alice"), string("file1")])
            ],
            vec![],
            vec![]
        )
    );

}

fn verifier_authority_checks<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## verifier authority checks: test11_verifier_authority_checks.bc");

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let data = if test {
        let v = load_testcase(target, "test11_verifier_authority_checks");
        let expected = Biscuit::from(&v[..]).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        println!("biscuit:\n```\n{}\n```\n", biscuit1.print());

        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test11_verifier_authority_checks", &data[..]);
        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file2")]),
                fact("operation", &[s("ambient"), s("read")]),
            ],
            vec![],
            vec![vec![rule(
              "check1",
              &[variable("0"), variable("1")],
              &[
              pred("right", &[s("authority"), var("0"), var("1")]),
              pred("resource", &[s("ambient"), var("0")]),
              pred("operation", &[s("ambient"), var("1")]),
              ],
            )]],
        )
    );

}

fn authority_checks<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## authority checks: test12_authority_checks.bc");

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_check(rule(
        "check1",
        &[string("file1")],
        &[pred("resource", &[s("ambient"), string("file1")])],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let data = if test {
        let v = load_testcase(target, "test12_authority_checks");
        let expected = Biscuit::from(&v[..]).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        println!("biscuit:\n```\n{}\n```\n", biscuit1.print());

        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test12_authority_checks", &data[..]);
        data
    };

    println!(
        "validation for \"file1\": `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
            fact("resource", &[s("ambient"), string("file1")]),
            fact("operation", &[s("ambient"), s("read")]),
            ],
            vec![],
            vec![]
            )
        );

    println!(
        "validation for \"file2\": `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file2")]),
                fact("operation", &[s("ambient"), s("read")]),
            ],
            vec![],
            vec![]
        )
    );

}

fn block_rules<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## block rules: test13_block_rules.bc");

    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));
    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file2"), s("read")],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    // timestamp for Thursday, December 31, 2030 12:59:59 PM UTC
    let date1 = SystemTime::UNIX_EPOCH + Duration::from_secs(1924952399);

    // generate valid_date("file1") if before date1
    block2.add_rule(constrained_rule(
        "valid_date",
        &[string("file1")],
        &[
            pred("time", &[s("ambient"), variable("0")]),
            pred("resource", &[s("ambient"), string("file1")]),
        ],
        &[
            Expression { ops: vec![
                Op::Value(var("0")),
                Op::Value(date(&date1)),
                Op::Binary(Binary::LessOrEqual)
            ] },
        ],
    ));

    // timestamp for Friday, December 31, 1999 12:59:59 PM UTC
    let date2 = SystemTime::UNIX_EPOCH + Duration::from_secs(946645199);

    let mut strings = BTreeSet::new();
    strings.insert(string("file1"));

    // generate a valid date fact for any file other than "file1" if before date2
    block2.add_rule(constrained_rule(
        "valid_date",
        &[variable("1")],
        &[
            pred("time", &[s("ambient"), variable("0")]),
            pred("resource", &[s("ambient"), variable("1")]),
        ],
        &[
            Expression { ops: vec![
                Op::Value(var("0")),
                Op::Value(date(&date2)),
                Op::Binary(Binary::LessOrEqual)
            ] },
            Expression { ops: vec![
                Op::Value(var("1")),
                Op::Value(set(strings)),
                Op::Binary(Binary::NotIn)
            ] },
        ],
    ));

    block2.add_check(rule(
        "check1",
        &[variable("0")],
        &[
            pred("valid_date", &[variable("0")]),
            pred("resource", &[s("ambient"), var("0")]),
        ]
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test13_block_rules");
        let expected = Biscuit::from(&v[..]).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        println!("biscuit2 (1 check):\n```\n{}\n```\n", biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test13_block_rules", &data[..]);

        data
    };

    println!(
        "validation for \"file1\": `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
                fact("time", &[s("ambient"), date(&UNIX_EPOCH.checked_add(Duration::from_secs(1608542592)).unwrap())])
            ],
            vec![],
            vec![]
        )
    );

    println!(
        "validation for \"file2\": `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file2")]),
                fact("time", &[s("ambient"), date(&UNIX_EPOCH.checked_add(Duration::from_secs(1608542592)).unwrap())])
            ],
            vec![],
            vec![]
        )
    );
}

fn regex_constraint<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## regex_constraint: test14_regex_constraint.bc");

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_check(constrained_rule(
        "resource_match",
        &[variable("0")],
        &[
            pred("resource", &[s("ambient"), variable("0")]),
        ],
        &[Expression { ops: vec![
            Op::Value(var("0")),
            Op::Value(string("file[0-9]+.txt")),
            Op::Binary(Binary::Regex)
        ] } ],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let data = if test {
        let v = load_testcase(target, "test14_regex_constraint");
        let expected = Biscuit::from(&v[..]).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        println!("biscuit:\n```\n{}\n```\n", biscuit1.print());

        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test14_regex_constraint", &data[..]);
        data
    };

    println!(
        "validation for \"file1\": `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
            ],
            vec![],
            vec![]
        )
    );

    println!(
        "validation for \"file123.txt\": `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file123.txt")]),
            ],
            vec![],
            vec![]
        )
    );
}

fn multi_queries_checks<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## multi queries checks: test15_multi_queries_checks.bc");

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact(
        "must_be_present",
        &[s("authority"), string("hello")],
        //&[string("hello")],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let data = if test {
        let v = load_testcase(target, "test15_multi_queries_checks");
        let expected = Biscuit::from(&v[..]).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        println!("biscuit:\n```\n{}\n```\n", biscuit1.print());

        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test15_multi_queries_checks", &data[..]);

        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![],
            vec![],
            vec![
                vec![rule(
                  "test_must_be_present_authority",
                  &[variable("0")],
                  &[pred("must_be_present", &[s("authority"), var("0")])],
                ),
                  rule(
                  "test_must_be_present",
                  &[variable("0")],
                  &[pred("must_be_present", &[var("0")])],
                )],
            ],
        )
    );
}

fn check_head_name<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair, test: bool) {
    println!("## check head name should be independent from fact names: test16_check_head_name.bc");

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_check(rule(
        "check1",
        &[s("test")],
        &[
            pred("resource", &[s("ambient"), s("hello")]),
        ],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    //println!("biscuit1 (authority): {}", biscuit1.print());

    let mut block2 = biscuit1.create_block();
    block2.add_fact(fact("check1", &[s("test")])).unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_rng(rng, &keypair2, block2)
        .unwrap();

    let data = if test {
        let v = load_testcase(target, "test16_check_head_name");
        let expected = Biscuit::from(&v[..]).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        println!("biscuit: {}", biscuit2.print());
        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test16_check_head_name", &data[..]);
        data
    };

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![],
            vec![],
            vec![],
        )
    );
}
