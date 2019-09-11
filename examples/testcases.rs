extern crate rand;
extern crate biscuit;
extern crate hex;

use rand::prelude::*;
use biscuit::token::{Biscuit, default_symbol_table, builder::*, verifier::Verifier};
use biscuit::crypto::KeyPair;
use biscuit::error;
use std::fs::File;
use std::io::Write;

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
    println!("root secret key: {}", hex::encode(root.private.to_bytes()));
    println!("root public key: {}", hex::encode(root.public.compress().to_bytes()));

    println!("------------------------------");
    basic_token(&mut rng, &target, &root);
}

fn validate_token(root: &KeyPair, data: &[u8], ambient_facts: Vec<Fact>, ambient_rules: Vec<Rule>, ambient_caveats: Vec<Rule>) -> Result<(), error::Token> {
  let token = Biscuit::from(&data[..], root.public)?;

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

  verifier.verify(token).map_err(error::Token::FailedLogic)
}

fn write_testcase(target: &str, name: &str, data: &[u8]) {
  println!("written to: {}/{}", target, name);

  let path  = target.to_string();
  let mut file = File::create(&format!("{}/{}.bc", target, name)).unwrap();
  file.write_all(data).unwrap();
  file.flush().unwrap();
}

fn basic_token<T:Rng+CryptoRng>(rng: &mut T, target: &str, root: &KeyPair) {
  println!("basic token:");

  let symbols = default_symbol_table();
  let mut authority_block = BlockBuilder::new(0, symbols);

  authority_block.add_fact(&fact("right", &[s("authority"), s("file1"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), s("file2"), s("read")]));
  authority_block.add_fact(&fact("right", &[s("authority"), s("file1"), s("write")]));

  let biscuit1 = Biscuit::new(rng, &root, &authority_block.to_block()).unwrap();

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
    .append(rng, &keypair2, block2.to_block())
    .unwrap();

  println!("biscuit2 (1 caveat): {}", biscuit2.print());

  let data = biscuit2.to_vec().unwrap();
  println!("validation: {:?}", validate_token(root, &data[..], vec![fact("resource", &[s("ambient"), string("file1")])], vec![], vec![]));
  write_testcase(target, "test1_basic", &data[..]);
}
