#![feature(test)]
extern crate test;

extern crate biscuit;
extern crate rand;

use rand::rngs::OsRng;
use test::Bencher;
use biscuit::{crypto::KeyPair, token::{Biscuit, builder::*}};

#[bench]
fn create_block_1(b: &mut Bencher) {
  let mut rng: OsRng = OsRng::new().unwrap();
  let root = KeyPair::new(&mut rng);

  let mut builder = Biscuit::builder(&mut rng, &root);
  builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("read")],));
  builder.add_authority_fact(&fact("right", &[s("authority"), string("file2"), s("read")],));
  builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("write")],));

  let token = builder.build().unwrap();
  let data = token.to_vec().unwrap();

  b.bytes = data.len() as u64;
  assert_eq!(b.bytes, 208);
  b.iter(|| {
    let mut builder = Biscuit::builder(&mut rng, &root);
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build().unwrap();
    let data = token.to_vec().unwrap();
  });
}

#[bench]
fn append_block_2(b: &mut Bencher) {
  let mut rng: OsRng = OsRng::new().unwrap();
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);

  let mut builder = Biscuit::builder(&mut rng, &root);
  builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("read")],));
  builder.add_authority_fact(&fact("right", &[s("authority"), string("file2"), s("read")],));
  builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("write")],));

  let token = builder.build().unwrap();
  let base_data = token.to_vec().unwrap();
  
  let mut block_builder = token.create_block();
  block_builder.check_resource("file1");
  block_builder.check_operation("read");

  let token2 = token.append(&mut rng, &keypair2, block_builder.build()).unwrap();
  let data = token2.to_vec().unwrap();

  b.bytes = (data.len() - base_data.len()) as u64;
  assert_eq!(b.bytes, 166);
  b.iter(|| {
    let token = Biscuit::from(&data).unwrap();
    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder.build()).unwrap();
    let data = token2.to_vec().unwrap();
  });
}

#[bench]
fn verify_block_2(b: &mut Bencher) {
  let mut rng: OsRng = OsRng::new().unwrap();
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);

  let data = {
    let mut builder = Biscuit::builder(&mut rng, &root);
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build().unwrap();
    let base_data = token.to_vec().unwrap();
    
    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder.build()).unwrap();
    token2.to_vec().unwrap()
  };

  let token = Biscuit::from(&data).unwrap();
  let mut verifier = token.verify(root.public()).unwrap();
  verifier.add_resource("file1");
  verifier.add_operation("read");
  verifier.verify().unwrap();

  b.bytes = data.len() as u64;
  b.iter(|| {
    let token = Biscuit::from(&data).unwrap();
    let mut verifier = token.verify(root.public()).unwrap();
    verifier.add_resource("file1");
    verifier.add_operation("read");
    verifier.verify().unwrap();
  });
}

#[bench]
fn check_signature_2(b: &mut Bencher) {
  let mut rng: OsRng = OsRng::new().unwrap();
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);

  let data = {
    let mut builder = Biscuit::builder(&mut rng, &root);
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build().unwrap();
    let base_data = token.to_vec().unwrap();
    
    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder.build()).unwrap();
    token2.to_vec().unwrap()
  };

  let token = Biscuit::from(&data).unwrap();
  let mut verifier = token.verify(root.public()).unwrap();
  verifier.add_resource("file1");
  verifier.add_operation("read");
  verifier.verify().unwrap();

  b.bytes = data.len() as u64;
  b.iter(|| {
    let token = Biscuit::from(&data).unwrap();
    token.check_root_key(root.public()).unwrap();
  });
}

#[bench]
fn caveats_block_2(b: &mut Bencher) {
  let mut rng: OsRng = OsRng::new().unwrap();
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);

  let data = {
    let mut builder = Biscuit::builder(&mut rng, &root);
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build().unwrap();
    let base_data = token.to_vec().unwrap();
    
    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder.build()).unwrap();
    token2.to_vec().unwrap()
  };

  let token = Biscuit::from(&data).unwrap();
  let mut verifier = token.verify(root.public()).unwrap();
  verifier.add_resource("file1");
  verifier.add_operation("read");
  verifier.verify().unwrap();

  let token = Biscuit::from(&data).unwrap();
  b.bytes = data.len() as u64;
  b.iter(|| {
    let mut verifier = token.verify(root.public()).unwrap();
    verifier.add_resource("file1");
    verifier.add_operation("read");
    verifier.verify().unwrap();
  });
}
