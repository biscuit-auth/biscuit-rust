#![feature(test)]
extern crate test;

extern crate biscuit_auth as biscuit;
extern crate rand;

use rand::rngs::OsRng;
use test::Bencher;
use biscuit::{crypto::KeyPair, token::{Biscuit, builder::*}};

#[bench]
fn create_block_1(b: &mut Bencher) {
  let mut rng = OsRng;
  let root = KeyPair::new(&mut rng);

  let mut builder = Biscuit::builder(&root);
  builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
  builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
  builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

  let token = builder.build(&mut rng).unwrap();
  let data = token.to_vec().unwrap();

  b.bytes = data.len() as u64;
  assert_eq!(b.bytes, 208);
  b.iter(|| {
    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build(&mut rng).unwrap();
    let data = token.to_vec().unwrap();
  });
}

#[bench]
fn append_block_2(b: &mut Bencher) {
  let mut rng: OsRng = OsRng;
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);

  let mut builder = Biscuit::builder(&root);
  builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
  builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
  builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

  let token = builder.build(&mut rng).unwrap();
  let base_data = token.to_vec().unwrap();
  
  let mut block_builder = token.create_block();
  block_builder.check_resource("file1");
  block_builder.check_operation("read");

  let token2 = token.append(&mut rng, &keypair2, block_builder).unwrap();
  let data = token2.to_vec().unwrap();

  b.bytes = (data.len() - base_data.len()) as u64;
  assert_eq!(b.bytes, 170);
  b.iter(|| {
    let token = Biscuit::from(&base_data).unwrap();
    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder).unwrap();
    let data = token2.to_vec().unwrap();
  });
}

#[bench]
fn append_block_5(b: &mut Bencher) {
  let mut rng: OsRng = OsRng;
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);
  let keypair3 = KeyPair::new(&mut rng);
  let keypair4 = KeyPair::new(&mut rng);
  let keypair5 = KeyPair::new(&mut rng);

  let mut builder = Biscuit::builder(&root);
  builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
  builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
  builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

  let token = builder.build(&mut rng).unwrap();
  let base_data = token.to_vec().unwrap();
  
  let mut block_builder = token.create_block();
  block_builder.check_resource("file1");
  block_builder.check_operation("read");

  let token2 = token.append(&mut rng, &keypair2, block_builder).unwrap();
  let data = token2.to_vec().unwrap();

  b.bytes = (data.len() - base_data.len()) as u64;
  assert_eq!(b.bytes, 170);
  b.iter(|| {
    let token2 = Biscuit::from(&data).unwrap();
    let mut b = token2.create_block();
    b.check_resource("file1");
    b.check_operation("read");

    let token3 = token2.append(&mut rng, &keypair3, b).unwrap();
    let data = token3.to_vec().unwrap();

    let token3 = Biscuit::from(&data).unwrap();
    let mut b = token3.create_block();
    b.check_resource("file1");
    b.check_operation("read");

    let token4 = token3.append(&mut rng, &keypair4, b).unwrap();
    let data = token4.to_vec().unwrap();

    let token4 = Biscuit::from(&data).unwrap();
    let mut b = token4.create_block();
    b.check_resource("file1");
    b.check_operation("read");

    let token5 = token4.append(&mut rng, &keypair5, b).unwrap();
    let data = token5.to_vec().unwrap();
  });
}

#[bench]
fn verify_block_2(b: &mut Bencher) {
  let mut rng: OsRng = OsRng;
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);

  let data = {
    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build(&mut rng).unwrap();
    let base_data = token.to_vec().unwrap();

    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder).unwrap();
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
fn verify_block_5(b: &mut Bencher) {
  let mut rng: OsRng = OsRng;
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);
  let keypair3 = KeyPair::new(&mut rng);
  let keypair4 = KeyPair::new(&mut rng);
  let keypair5 = KeyPair::new(&mut rng);

  let data = {
    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build(&mut rng).unwrap();
    let base_data = token.to_vec().unwrap();

    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder).unwrap();

    let mut block_builder = token2.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token3 = token2.append(&mut rng, &keypair3, block_builder).unwrap();

    let mut block_builder = token3.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token4 = token3.append(&mut rng, &keypair4, block_builder).unwrap();

    let mut block_builder = token4.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token5 = token4.append(&mut rng, &keypair5, block_builder).unwrap();
    token5.to_vec().unwrap()
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
  let mut rng: OsRng = OsRng;
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);

  let data = {
    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build(&mut rng).unwrap();
    let base_data = token.to_vec().unwrap();

    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder).unwrap();
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
fn check_signature_5(b: &mut Bencher) {
  let mut rng: OsRng = OsRng;
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);
  let keypair3 = KeyPair::new(&mut rng);
  let keypair4 = KeyPair::new(&mut rng);
  let keypair5 = KeyPair::new(&mut rng);

  let data = {
    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build(&mut rng).unwrap();
    let base_data = token.to_vec().unwrap();
    
    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder).unwrap();
    let mut block_builder = token2.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token3 = token2.append(&mut rng, &keypair3, block_builder).unwrap();

    let mut block_builder = token3.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token4 = token3.append(&mut rng, &keypair4, block_builder).unwrap();

    let mut block_builder = token4.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token5 = token4.append(&mut rng, &keypair5, block_builder).unwrap();
    token5.to_vec().unwrap()
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
  let mut rng: OsRng = OsRng;
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);

  let data = {
    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build(&mut rng).unwrap();
    let base_data = token.to_vec().unwrap();
    
    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder).unwrap();
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

#[bench]
fn caveats_block_create_verifier2(b: &mut Bencher) {
  let mut rng: OsRng = OsRng;
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);

  let data = {
    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build(&mut rng).unwrap();
    let base_data = token.to_vec().unwrap();

    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder).unwrap();
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
  });
}

#[bench]
fn caveats_block_verify_only2(b: &mut Bencher) {
  let mut rng: OsRng = OsRng;
  let root = KeyPair::new(&mut rng);
  let keypair2 = KeyPair::new(&mut rng);

  let data = {
    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")],));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("write")],));

    let token = builder.build(&mut rng).unwrap();
    let base_data = token.to_vec().unwrap();

    let mut block_builder = token.create_block();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append(&mut rng, &keypair2, block_builder).unwrap();
    token2.to_vec().unwrap()
  };

  let token = Biscuit::from(&data).unwrap();
  let mut verifier = token.verify(root.public()).unwrap();
  verifier.add_resource("file1");
  verifier.add_operation("read");
  verifier.verify().unwrap();

  let token = Biscuit::from(&data).unwrap();
  let mut verifier = token.verify(root.public()).unwrap();
  b.iter(|| {
    verifier.add_resource("file1");
    verifier.add_operation("read");
    verifier.verify().unwrap();
  });
}
