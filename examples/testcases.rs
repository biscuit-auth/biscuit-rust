#![allow(unused_must_use)]
extern crate biscuit_auth as biscuit;
extern crate curve25519_dalek;
extern crate hex;
extern crate prost;
extern crate rand;

use biscuit::crypto::KeyPair;
use biscuit::error;
use biscuit::token::{builder::*, default_symbol_table, Biscuit};
use curve25519_dalek::scalar::Scalar;
use prost::Message;
use rand::prelude::*;
use std::{
  fs::File,
  io::Write,
  time::*,
  collections::HashSet
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

    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let root = KeyPair::new(&mut rng);
    println!("# Biscuit samples and expected results\n");
    println!(
        "root secret key: {}",
        hex::encode(root.private().to_bytes())
    );
    println!("root public key: {}", hex::encode(root.public().to_bytes()));

    println!("\n------------------------------\n");
    basic_token(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    different_root_key(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    invalid_signature_format(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    random_block(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    invalid_signature(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    reordered_blocks(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    missing_authority_tag(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    invalid_block_fact_authority(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    invalid_block_fact_ambient(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    separate_block_validation(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    expired_token(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    authority_rules(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    verifier_authority_caveats(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    authority_caveats(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    block_rules(&mut rng, &target, &root);

    println!("\n------------------------------\n");
    regex_constraint(&mut rng, &target, &root);
}

fn validate_token(
    root: &KeyPair,
    data: &[u8],
    ambient_facts: Vec<Fact>,
    ambient_rules: Vec<Rule>,
    authority_caveats: Vec<Rule>,
    block_caveats: Vec<Rule>,
) -> Result<(), error::Token> {
    let token = Biscuit::from(&data[..])?;

    let mut verifier = token.verify(root.public())?;
    for fact in ambient_facts {
        verifier.add_fact(fact);
    }
    for rule in ambient_rules {
        verifier.add_rule(rule);
    }
    for caveat in authority_caveats {
        verifier.add_authority_caveat(caveat);
    }
    for caveat in block_caveats {
        verifier.add_block_caveat(caveat);
    }

    verifier.verify()?;
    Ok(())
}

fn write_testcase(target: &str, name: &str, data: &[u8]) {
    //println!("written to: {}/{}", target, name);

    let mut file = File::create(&format!("{}/{}.bc", target, name)).unwrap();
    file.write_all(data).unwrap();
    file.flush().unwrap();
}

fn basic_token<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## basic token: test1_basic.bc");

    let mut builder = Biscuit::builder(rng, &root);

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

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[var(0)],
        &[
            pred("resource", &[s("ambient"), var(0)]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var(0), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let data = biscuit2.to_vec().unwrap();
    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test1_basic", &data[..]);
}

fn different_root_key<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## different root key: test2_different_root_key.bc");

    let root2 = KeyPair::new(rng);
    let mut builder = Biscuit::builder(rng, &root2);

    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));

    let biscuit1 = builder.build().unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[var(0)],
        &[
            pred("resource", &[s("ambient"), var(0)]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var(0), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let data = biscuit2.to_vec().unwrap();
    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test2_different_root_key", &data[..]);
}

fn invalid_signature_format<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## invalid signature format: test3_invalid_signature_format.bc");

    let mut builder = Biscuit::builder(rng, &root);

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

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[var(0)],
        &[
            pred("resource", &[s("ambient"), var(0)]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var(0), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let serialized = biscuit2.container().unwrap();
    let mut proto = serialized.to_proto();
    proto.signature.z.truncate(16);
    let mut data = Vec::new();
    proto.encode(&mut data).unwrap();

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test3_invalid_signature_format", &data[..]);
}

fn random_block<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## random block: test4_random_block.bc");

    let mut builder = Biscuit::builder(rng, &root);

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

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[var(0)],
        &[
            pred("resource", &[s("ambient"), var(0)]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var(0), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let serialized = biscuit2.container().unwrap();
    let mut proto = serialized.to_proto();
    let arr: [u8; 32] = rng.gen();
    proto.blocks[0] = Vec::from(&arr[..]);
    let mut data = Vec::new();
    proto.encode(&mut data).unwrap();

    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test4_random_block", &data[..]);
}

fn invalid_signature<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## invalid signature: test5_invalid_signature.bc");

    let mut builder = Biscuit::builder(rng, &root);

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

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[var(0)],
        &[
            pred("resource", &[s("ambient"), var(0)]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var(0), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let mut serialized = biscuit2.container().unwrap().clone();
    serialized.signature.z = serialized.signature.z + Scalar::one();

    let data = serialized.to_vec().unwrap();
    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test5_invalid_signature", &data[..]);
}

fn reordered_blocks<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## reordered blocks: test6_reordered_blocks.bc");

    let mut builder = Biscuit::builder(rng, &root);

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

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[var(0)],
        &[
            pred("resource", &[s("ambient"), var(0)]),
            pred("operation", &[s("ambient"), s("read")]),
            pred("right", &[s("authority"), var(0), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let mut block3 = biscuit2.create_block();

    block3.add_caveat(rule(
        "caveat2",
        &[var(0)],
        &[pred("resource", &[s("ambient"), string("file1")])],
    ));

    let keypair3 = KeyPair::new(rng);
    let biscuit3 = biscuit2.append(rng, &keypair3, block3.build()).unwrap();

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

    let data = serialized.to_vec().unwrap();
    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test6_reordered_blocks", &data[..]);
}

fn missing_authority_tag<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## missing authority tag: test7_missing_authority_tag.bc");

    let symbols = default_symbol_table();
    let mut authority_block = BlockBuilder::new(0, symbols.clone());
    authority_block.add_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));
    authority_block.add_fact(fact(
        "right",
        &[s("authority"), string("file2"), s("read")],
    ));
    authority_block.add_fact(fact("right", &[string("file1"), s("write")]));
    let biscuit1 = Biscuit::new(rng, &root, symbols, authority_block.build()).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[var(0)],
        &[pred("operation", &[s("ambient"), s("read")])],
    ));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let data = biscuit2.to_vec().unwrap();
    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test7_missing_authority_tag", &data[..]);
}

fn invalid_block_fact_authority<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## invalid block fact with authority tag: test8_invalid_block_fact_authority.bc");

    let mut builder = Biscuit::builder(rng, &root);

    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));

    let biscuit1 = builder.build().unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[var(0)],
        &[pred("operation", &[s("ambient"), s("read")])],
    ));

    block2.add_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("write")],
    ));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let data = biscuit2.to_vec().unwrap();
    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test8_invalid_block_fact_authority", &data[..]);
}

fn invalid_block_fact_ambient<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## invalid block fact with ambient tag: test9_invalid_block_fact_ambient.bc");

    let mut builder = Biscuit::builder(rng, &root);

    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));

    let biscuit1 = builder.build().unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[var(0)],
        &[pred("operation", &[s("ambient"), s("read")])],
    ));

    block2.add_fact(fact("right", &[s("ambient"), string("file1"), s("write")]));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let data = biscuit2.to_vec().unwrap();
    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test9_invalid_block_fact_ambient", &data[..]);
}

fn separate_block_validation<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## separate block validation (facts from one block should not be usable in another one): test10_separate_block_validation.bc");

    let builder = Biscuit::builder(rng, &root);
    let biscuit1 = builder.build().unwrap();
    let mut block2 = biscuit1.create_block();

    block2.add_fact(fact("test", &[s("write")]));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    let mut block3 = biscuit2.create_block();
    block3.add_caveat(rule("caveat1", &[var(0)], &[pred("test", &[var(0)])]));

    let keypair3 = KeyPair::new(rng);
    let biscuit3 = biscuit2.append(rng, &keypair3, block3.build()).unwrap();

    println!("biscuit3:\n```\n{}\n```\n", biscuit3.print());

    let data = biscuit3.to_vec().unwrap();
    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test10_separate_block_validation", &data[..]);
}

fn expired_token<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## expired token: test11_expired_token.bc");

    let builder = Biscuit::builder(rng, &root);
    let biscuit1 = builder.build().unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[string("file1")],
        &[pred("resource", &[s("ambient"), string("file1")])],
    ));
    // January 1 2019
    block2.expiration_date(
        UNIX_EPOCH
            .checked_add(Duration::from_secs(49 * 365 * 24 * 3600))
            .unwrap(),
    );

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let data = biscuit2.to_vec().unwrap();
    println!(
        "validation: `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
                fact("operation", &[s("ambient"), s("read")]),
                fact("time", &[s("ambient"), date(&SystemTime::now())])
            ],
            vec![],
            vec![],
            vec![]
        )
    );
    write_testcase(target, "test11_expired_token", &data[..]);
}

fn authority_rules<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## authority rules: test12_authority_rules.bc");

    let mut builder = Biscuit::builder(rng, &root);
    builder.add_authority_rule(rule(
        "right",
        &[symbol("authority"), variable(1), symbol("read")],
        &[
            pred("resource", &[s("ambient"), variable(1)]),
            pred("owner", &[s("ambient"), variable(0), variable(1)]),
        ],
    ));
    builder.add_authority_rule(rule(
        "right",
        &[symbol("authority"), variable(1), symbol("write")],
        &[
            pred("resource", &[s("ambient"), variable(1)]),
            pred("owner", &[s("ambient"), variable(0), variable(1)]),
        ],
    ));

    let biscuit1 = builder.build().unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_caveat(rule(
        "caveat1",
        &[variable(0), variable(1)],
        &[
            pred("right", &[s("authority"), var(0), var(1)]),
            pred("resource", &[s("ambient"), var(0)]),
            pred("operation", &[s("ambient"), var(1)]),
        ],
    ));
    block2.add_caveat(rule(
        "caveat2",
        &[variable(0)],
        &[
            pred("resource", &[s("ambient"), var(0)]),
            pred("owner", &[s("ambient"), symbol("alice"), var(0)]),
        ],
    ));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let data = biscuit2.to_vec().unwrap();
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
            vec![],
            vec![]
        )
    );

    write_testcase(target, "test12_authority_rules", &data[..]);
}

fn verifier_authority_caveats<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## verifier authority caveats: test13_verifier_authority_caveats.bc");

    let mut builder = Biscuit::builder(rng, &root);

    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));

    let biscuit1 = builder.build().unwrap();
    println!("biscuit:\n```\n{}\n```\n", biscuit1.print());

    let data = biscuit1.to_vec().unwrap();
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
            vec![rule(
              "caveat1",
              &[variable(0), variable(1)],
              &[
              pred("right", &[s("authority"), var(0), var(1)]),
              pred("resource", &[s("ambient"), var(0)]),
              pred("operation", &[s("ambient"), var(1)]),
              ],
            )],
            vec![]
        )
    );

    write_testcase(target, "test13_verifier_authority_caveats", &data[..]);
}

fn authority_caveats<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## authority caveats: test14_authority_caveats.bc");

    let mut builder = Biscuit::builder(rng, &root);

    builder.add_authority_caveat(rule(
        "caveat1",
        &[string("file1")],
        &[pred("resource", &[s("ambient"), string("file1")])],
    ));

    let biscuit1 = builder.build().unwrap();
    println!("biscuit:\n```\n{}\n```\n", biscuit1.print());

    let data = biscuit1.to_vec().unwrap();
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
            vec![],
            vec![]
        )
    );

    write_testcase(target, "test14_authority_caveats", &data[..]);
}

fn block_rules<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## block rules: test15_block_rules.bc");

    let mut builder = Biscuit::builder(rng, &root);
    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file1"), s("read")],
    ));
    builder.add_authority_fact(fact(
        "right",
        &[s("authority"), string("file2"), s("read")],
    ));

    let biscuit1 = builder.build().unwrap();

    let mut block2 = biscuit1.create_block();

    // timestamp for Thursday, December 31, 2030 12:59:59 PM UTC
    let date1 = SystemTime::UNIX_EPOCH + Duration::from_secs(1924952399);

    // generate valid_date("file1") if before date1
    block2.add_rule(constrained_rule(
        "valid_date",
        &[string("file1")],
        &[
            pred("time", &[s("ambient"), variable(0)]),
            pred("resource", &[s("ambient"), string("file1")]),
        ],
        &[Constraint {
          id: 0,
          kind: ConstraintKind::Date(DateConstraint::Before(date1)),
        }]
    ));

    // timestamp for Friday, December 31, 1999 12:59:59 PM UTC
    let date2 = SystemTime::UNIX_EPOCH + Duration::from_secs(946645199);

    let mut strings = HashSet::new();
    strings.insert("file1".to_string());

    // generate a valid date fact for any file other than "file1" if before date2
    block2.add_rule(constrained_rule(
        "valid_date",
        &[variable(1)],
        &[
            pred("time", &[s("ambient"), variable(0)]),
            pred("resource", &[s("ambient"), variable(1)]),
        ],
        &[
          Constraint {
            id: 0,
            kind: ConstraintKind::Date(DateConstraint::Before(date2)),
          },
          Constraint {
            id: 1,
            kind: ConstraintKind::String(StrConstraint::NotIn(strings))
          }
        ]
    ));

    block2.add_caveat(rule(
        "caveat1",
        &[variable(0)],
        &[
            pred("valid_date", &[variable(0)]),
            pred("resource", &[s("ambient"), var(0)]),
        ]
    ));

    let keypair2 = KeyPair::new(rng);
    let biscuit2 = biscuit1.append(rng, &keypair2, block2.build()).unwrap();

    println!("biscuit2 (1 caveat):\n```\n{}\n```\n", biscuit2.print());

    let data = biscuit2.to_vec().unwrap();
    println!(
        "validation for \"file1\": `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
                fact("time", &[s("ambient"), date(&SystemTime::now())])
            ],
            vec![],
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
                fact("time", &[s("ambient"), date(&SystemTime::now())])
            ],
            vec![],
            vec![],
            vec![]
        )
    );

    write_testcase(target, "test15_block_rules", &data[..]);
}

fn regex_constraint<T: Rng + CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
    println!("## regex_constraint: test16_regex_constraint.bc");

    let mut builder = Biscuit::builder(rng, &root);

    builder.add_authority_caveat(constrained_rule(
        "resource_match",
        &[variable(0)],
        &[
            pred("resource", &[s("ambient"), variable(0)]),
        ],
        &[
          Constraint {
            id: 0,
            kind: ConstraintKind::String(StrConstraint::Regex("file[0-9]+.txt".to_string())),
          },
        ]
    ));

    let biscuit1 = builder.build().unwrap();
    println!("biscuit:\n```\n{}\n```\n", biscuit1.print());

    let data = biscuit1.to_vec().unwrap();
    println!(
        "validation for \"file1\": `{:?}`",
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
            ],
            vec![],
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
            vec![],
            vec![]
        )
    );

    write_testcase(target, "test16_regex_constraint", &data[..]);
}
