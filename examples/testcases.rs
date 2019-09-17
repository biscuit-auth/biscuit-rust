extern crate rand;
extern crate biscuit;
extern crate hex;
extern crate curve25519_dalek;
extern crate prost;

use rand::prelude::*;
use curve25519_dalek::scalar::Scalar;
use prost::Message;
use biscuit::token::{Biscuit, default_symbol_table, builder::*, verifier::Verifier};
use biscuit::crypto::KeyPair;
use biscuit::error;
use std::fs::File;
use std::io::Write;
use std::time::*;

fn main() {
    println!("args: {:?}", std::env::args());
    let mut args = std::env::args();
    args.next();
    let target = match args.next() {
      Some(arg) => arg,
      None => {
        println!("missing target directory argument");
        return;
      }
    };

    println!("will write testcases to {}", target);

    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let root = KeyPair::new(&mut rng);
    println!("root secret key: {}", hex::encode(root.private().to_bytes()));
    println!("root public key: {}", hex::encode(root.public().to_bytes()));

    println!("------------------------------");
    basic_token(&mut rng, &target, &root);

    println!("------------------------------");
    different_root_key(&mut rng, &target, &root);

    println!("------------------------------");
    invalid_signature_format(&mut rng, &target, &root);

    println!("------------------------------");
    invalid_signature(&mut rng, &target, &root);

    println!("------------------------------");
    random_block(&mut rng, &target, &root);

    println!("------------------------------");
    reordered_blocks(&mut rng, &target, &root);

    println!("------------------------------");
    missing_authority_tag(&mut rng, &target, &root);

    println!("------------------------------");
    invalid_block_fact_authority(&mut rng, &target, &root);

    println!("------------------------------");
    invalid_block_fact_ambient(&mut rng, &target, &root);

    println!("------------------------------");
    separate_block_validation(&mut rng, &target, &root);

    println!("------------------------------");
    expired_token(&mut rng, &target, &root);
}

fn validate_token(root: &KeyPair, data: &[u8], ambient_facts: Vec<Fact>, ambient_rules: Vec<Rule>, ambient_caveats: Vec<Rule>) -> Result<(), error::Token> {
  let token = Biscuit::from(&data[..], root.public())?;

  let mut verifier = Verifier::new();
  for fact in ambient_facts {
    verifier.add_fact(fact);
  }
  for rule in ambient_rules {
    verifier.add_rule(rule);
  }
  for caveat in ambient_caveats {
    verifier.add_caveat(caveat);
  }

  verifier.verify(&token).map_err(error::Token::FailedLogic)
}

fn write_testcase(target: &str, name: &str, data: &[u8]) {
  println!("written to: {}/{}", target, name);

  let mut file = File::create(&format!("{}/{}.bc", target, name)).unwrap();
  file.write_all(data).unwrap();
  file.flush().unwrap();
}

fn basic_token<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("basic token:");

  let symbols = default_symbol_table();
  let mut authority_block = BlockBuilder::new(0, symbols);

  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file2"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("write")]));

  let biscuit1 = Biscuit::new(rng, &root, authority_block.build()).unwrap();

  let mut block2 = biscuit1.create_block();

  block2.add_caveat(&rule(
    "caveat1",
    &[var(0)],
    &[
      pred("resource", &[s("ambient"), var(0)]),
      pred("operation", &[s("ambient"), s("read")]),
      pred("right", &[s("authority"), var(0), s("read")]),
    ],
  ));

  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let data = biscuit2.to_vec().unwrap();
  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test1_basic", &data[..]);
}

fn different_root_key<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("different root key:");

  let root2 = KeyPair::new(rng);
  let symbols = default_symbol_table();
  let mut authority_block = BlockBuilder::new(0, symbols);

  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("read")]));

  let biscuit1 = Biscuit::new(rng, &root2, authority_block.build()).unwrap();

  let mut block2 = biscuit1.create_block();

  block2.add_caveat(&rule(
    "caveat1",
    &[var(0)],
    &[
      pred("resource", &[s("ambient"), var(0)]),
      pred("operation", &[s("ambient"), s("read")]),
      pred("right", &[s("authority"), var(0), s("read")]),
    ],
  ));

  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let data = biscuit2.to_vec().unwrap();
  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test2_different_root_key", &data[..]);
}

fn invalid_signature_format<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("invalid signature format:");

  let symbols = default_symbol_table();
  let mut authority_block = BlockBuilder::new(0, symbols);

  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file2"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("write")]));

  let biscuit1 = Biscuit::new(rng, &root, authority_block.build()).unwrap();

  let mut block2 = biscuit1.create_block();

  block2.add_caveat(&rule(
    "caveat1",
    &[var(0)],
    &[
      pred("resource", &[s("ambient"), var(0)]),
      pred("operation", &[s("ambient"), s("read")]),
      pred("right", &[s("authority"), var(0), s("read")]),
    ],
  ));

  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let serialized = biscuit2.container().unwrap();
  let mut proto = serialized.to_proto();
  proto.signature.z.truncate(16);
  let mut data = Vec::new();
  proto.encode(&mut data).unwrap();

  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test3_invalid_signature_format", &data[..]);
}

fn random_block<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("random block:");

  let symbols = default_symbol_table();
  let mut authority_block = BlockBuilder::new(0, symbols);

  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file2"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("write")]));

  let biscuit1 = Biscuit::new(rng, &root, authority_block.build()).unwrap();

  let mut block2 = biscuit1.create_block();

  block2.add_caveat(&rule(
    "caveat1",
    &[var(0)],
    &[
      pred("resource", &[s("ambient"), var(0)]),
      pred("operation", &[s("ambient"), s("read")]),
      pred("right", &[s("authority"), var(0), s("read")]),
    ],
  ));

  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let serialized = biscuit2.container().unwrap();
  let mut proto = serialized.to_proto();
  let arr: [u8; 32] = rng.gen();
  proto.blocks[0] = Vec::from(&arr[..]);
  let mut data = Vec::new();
  proto.encode(&mut data).unwrap();

  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test4_random_block", &data[..]);
}

fn invalid_signature<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("invalid signature:");

  let symbols = default_symbol_table();
  let mut authority_block = BlockBuilder::new(0, symbols);

  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file2"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("write")]));

  let biscuit1 = Biscuit::new(rng, &root, authority_block.build()).unwrap();

  let mut block2 = biscuit1.create_block();

  block2.add_caveat(&rule(
    "caveat1",
    &[var(0)],
    &[
      pred("resource", &[s("ambient"), var(0)]),
      pred("operation", &[s("ambient"), s("read")]),
      pred("right", &[s("authority"), var(0), s("read")]),
    ],
  ));

  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let mut serialized = biscuit2.container().unwrap().clone();
  serialized.signature.z = serialized.signature.z + Scalar::one();

  let data = serialized.to_vec().unwrap();
  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test5_invalid_signature", &data[..]);
}

fn reordered_blocks<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("reordered blocks:");

  let symbols = default_symbol_table();
  let mut authority_block = BlockBuilder::new(0, symbols);

  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file2"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("write")]));

  let biscuit1 = Biscuit::new(rng, &root, authority_block.build()).unwrap();

  let mut block2 = biscuit1.create_block();

  block2.add_caveat(&rule(
    "caveat1",
    &[var(0)],
    &[
      pred("resource", &[s("ambient"), var(0)]),
      pred("operation", &[s("ambient"), s("read")]),
      pred("right", &[s("authority"), var(0), s("read")]),
    ],
  ));

  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let mut block3 = biscuit2.create_block();

  block3.add_caveat(&rule(
    "caveat2",
    &[var(0)],
    &[pred("resource", &[s("ambient"), string("file1")])],
  ));

  let keypair3 = KeyPair::new(rng);
  let biscuit3 = biscuit2
    .append(rng, &keypair3, block3.build())
    .unwrap();

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
  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test6_reordered_blocks", &data[..]);
}

fn missing_authority_tag<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("missing authority tag:");

  let symbols = default_symbol_table();
  let mut authority_block = BlockBuilder::new(0, symbols);

  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), string("file2"), s("read")]));
  authority_block.add_fact(&fact("right", &[string("file1"), s("write")]));

  let biscuit1 = Biscuit::new(rng, &root, authority_block.build()).unwrap();

  let mut block2 = biscuit1.create_block();

  block2.add_caveat(&rule(
    "caveat1",
    &[var(0)],
    &[
      pred("operation", &[s("ambient"), s("read")]),
    ],
  ));

  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let data = biscuit2.to_vec().unwrap();
  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test7_missing_authority_tag", &data[..]);
}

fn invalid_block_fact_authority<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("invalid block fact with authority tag:");

  let symbols = default_symbol_table();
  let mut authority_block = BlockBuilder::new(0, symbols);

  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("read")]));

  let biscuit1 = Biscuit::new(rng, &root, authority_block.build()).unwrap();

  let mut block2 = biscuit1.create_block();

  block2.add_caveat(&rule(
    "caveat1",
    &[var(0)],
    &[
      pred("operation", &[s("ambient"), s("read")]),
    ],
  ));

  block2.add_fact(&fact("right", &[s("authority"), string("file1"), s("write")]));

  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let data = biscuit2.to_vec().unwrap();
  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test8_invalid_block_fact_authority", &data[..]);
}

fn invalid_block_fact_ambient<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("invalid block fact with ambient tag:");

  let symbols = default_symbol_table();
  let mut authority_block = BlockBuilder::new(0, symbols);

  authority_block.add_fact(&fact("right", &[s("authority"), string("file1"), s("read")]));

  let biscuit1 = Biscuit::new(rng, &root, authority_block.build()).unwrap();

  let mut block2 = biscuit1.create_block();

  block2.add_caveat(&rule(
    "caveat1",
    &[var(0)],
    &[
      pred("operation", &[s("ambient"), s("read")]),
    ],
  ));

  block2.add_fact(&fact("right", &[s("ambient"), string("file1"), s("write")]));

  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let data = biscuit2.to_vec().unwrap();
  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test9_invalid_block_fact_ambient", &data[..]);
}

fn separate_block_validation<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("separate block validation (facts from one block should not be usable in another one):");

  let symbols = default_symbol_table();
  let authority_block = BlockBuilder::new(0, symbols);
  let biscuit1 = Biscuit::new(rng, &root, authority_block.build()).unwrap();
  let mut block2 = biscuit1.create_block();

  block2.add_fact(&fact("test", &[s("write")]));

  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  let mut block3 = biscuit2.create_block();
  block3.add_caveat(&rule(
    "caveat1",
    &[var(0)],
    &[
      pred("test", &[var(0)]),
    ],
  ));

  let keypair3 = KeyPair::new(rng);
  let biscuit3 = biscuit2
    .append(rng, &keypair3, block3.build())
    .unwrap();

  println!("biscuit3: {}", biscuit3.print());

  let data = biscuit3.to_vec().unwrap();
  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test10_separate_block_validation", &data[..]);
}

fn expired_token<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("expired token:");

  let symbols = default_symbol_table();
  let authority_block = BlockBuilder::new(0, symbols);

  let biscuit1 = Biscuit::new(rng, &root, authority_block.build()).unwrap();

  let mut block2 = biscuit1.create_block();

  block2.add_caveat(&rule(
    "caveat1",
    &[string("file1")],
    &[pred("resource", &[s("ambient"), string("file1")])],
  ));
  // January 1 2019
  block2.expiration_date(UNIX_EPOCH.checked_add(Duration::from_secs(49 * 365 * 24 * 3600)).unwrap());


  let keypair2 = KeyPair::new(rng);
  let biscuit2 = biscuit1
    .append(rng, &keypair2, block2.build())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let data = biscuit2.to_vec().unwrap();
  println!("validation: {:?}", validate_token(root, &data[..],
    vec![fact("resource", &[s("ambient"), string("file1")]), fact("operation", &[s("ambient"), s("read")]), fact("time", &[s("ambient"), date(&SystemTime::now())])],
    vec![], vec![]));
  write_testcase(target, "test11_expired_token", &data[..]);
}

