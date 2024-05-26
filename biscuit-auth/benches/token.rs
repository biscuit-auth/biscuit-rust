extern crate biscuit_auth as biscuit;

use std::time::Duration;

use biscuit::{
    builder::*, builder_ext::BuilderExt, datalog::SymbolTable, AuthorizerLimits, Biscuit, KeyPair,
    UnverifiedBiscuit,
};
use codspeed_bencher_compat::{benchmark_group, benchmark_main, Bencher};
use rand::rngs::OsRng;

fn create_block_1(b: &mut Bencher) {
    let mut rng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);

    let mut builder = Biscuit::builder();
    builder.add_fact(fact("right", &[string("file1"), string("read")]));
    builder.add_fact(fact("right", &[string("file2"), string("read")]));
    builder.add_fact(fact("right", &[string("file1"), string("write")]));

    let token = builder
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    let data = token.to_vec().unwrap();

    b.bytes = data.len() as u64;
    assert_eq!(b.bytes, 206);
    b.iter(|| {
        let mut builder = Biscuit::builder();
        builder.add_fact(fact("right", &[string("file1"), string("read")]));
        builder.add_fact(fact("right", &[string("file2"), string("read")]));
        builder.add_fact(fact("right", &[string("file1"), string("write")]));

        let token = builder
            .build_with_rng(&root, SymbolTable::default(), &mut rng)
            .unwrap();
        let data = token.to_vec().unwrap();
    });
}

fn append_block_2(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);

    let mut builder = Biscuit::builder();
    builder.add_fact(fact("right", &[string("file1"), string("read")]));
    builder.add_fact(fact("right", &[string("file2"), string("read")]));
    builder.add_fact(fact("right", &[string("file1"), string("write")]));

    let token = builder
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    let base_data = token.to_vec().unwrap();

    let mut block_builder = BlockBuilder::new();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
    let data = token2.to_vec().unwrap();

    b.bytes = (data.len() - base_data.len()) as u64;
    assert_eq!(b.bytes, 189);
    b.iter(|| {
        let token = Biscuit::from(&base_data, &root.public()).unwrap();
        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
        let data = token2.to_vec().unwrap();
    });
}

fn append_block_5(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let keypair3 = KeyPair::new_with_rng(&mut rng);
    let keypair4 = KeyPair::new_with_rng(&mut rng);
    let keypair5 = KeyPair::new_with_rng(&mut rng);

    let mut builder = Biscuit::builder();
    builder.add_fact(fact("right", &[string("file1"), string("read")]));
    builder.add_fact(fact("right", &[string("file2"), string("read")]));
    builder.add_fact(fact("right", &[string("file1"), string("write")]));

    let token = builder
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    let base_data = token.to_vec().unwrap();

    let mut block_builder = BlockBuilder::new();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
    let data = token2.to_vec().unwrap();

    b.bytes = (data.len() - base_data.len()) as u64;
    assert_eq!(b.bytes, 189);
    b.iter(|| {
        let token2 = Biscuit::from(&data, &root.public()).unwrap();
        let mut b = BlockBuilder::new();
        b.check_resource("file1");
        b.check_operation("read");

        let token3 = token2.append_with_keypair(&keypair3, b).unwrap();
        let data = token3.to_vec().unwrap();

        let token3 = Biscuit::from(&data, &root.public()).unwrap();
        let mut b = BlockBuilder::new();
        b.check_resource("file1");
        b.check_operation("read");

        let token4 = token3.append_with_keypair(&keypair4, b).unwrap();
        let data = token4.to_vec().unwrap();

        let token4 = Biscuit::from(&data, &root.public()).unwrap();
        let mut b = BlockBuilder::new();
        b.check_resource("file1");
        b.check_operation("read");

        let token5 = token4.append_with_keypair(&keypair5, b).unwrap();
        let data = token5.to_vec().unwrap();
    });
}

fn unverified_append_block_2(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);

    let mut builder = Biscuit::builder();
    builder.add_fact(fact("right", &[string("file1"), string("read")]));
    builder.add_fact(fact("right", &[string("file2"), string("read")]));
    builder.add_fact(fact("right", &[string("file1"), string("write")]));

    let token = builder
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    let base_data = token.to_vec().unwrap();

    let mut block_builder = BlockBuilder::new();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
    let data = token2.to_vec().unwrap();

    b.bytes = (data.len() - base_data.len()) as u64;
    assert_eq!(b.bytes, 189);
    b.iter(|| {
        let token = UnverifiedBiscuit::from(&base_data).unwrap();
        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
        let data = token2.to_vec().unwrap();
    });
}

fn unverified_append_block_5(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let keypair3 = KeyPair::new_with_rng(&mut rng);
    let keypair4 = KeyPair::new_with_rng(&mut rng);
    let keypair5 = KeyPair::new_with_rng(&mut rng);

    let mut builder = Biscuit::builder();
    builder.add_fact(fact("right", &[string("file1"), string("read")]));
    builder.add_fact(fact("right", &[string("file2"), string("read")]));
    builder.add_fact(fact("right", &[string("file1"), string("write")]));

    let token = builder
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    let base_data = token.to_vec().unwrap();

    let mut block_builder = BlockBuilder::new();
    block_builder.check_resource("file1");
    block_builder.check_operation("read");

    let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
    let data = token2.to_vec().unwrap();

    b.bytes = (data.len() - base_data.len()) as u64;
    assert_eq!(b.bytes, 189);
    b.iter(|| {
        let token2 = UnverifiedBiscuit::from(&data).unwrap();
        let mut b = BlockBuilder::new();
        b.check_resource("file1");
        b.check_operation("read");

        let token3 = token2.append_with_keypair(&keypair3, b).unwrap();
        let data = token3.to_vec().unwrap();

        let token3 = UnverifiedBiscuit::from(&data).unwrap();
        let mut b = BlockBuilder::new();
        b.check_resource("file1");
        b.check_operation("read");

        let token4 = token3.append_with_keypair(&keypair4, b).unwrap();
        let data = token4.to_vec().unwrap();

        let token4 = UnverifiedBiscuit::from(&data).unwrap();
        let mut b = BlockBuilder::new();
        b.check_resource("file1");
        b.check_operation("read");

        let token5 = token4.append_with_keypair(&keypair5, b).unwrap();
        let data = token5.to_vec().unwrap();
    });
}

fn verify_block_2(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);

    let data = {
        let mut builder = Biscuit::builder();
        builder.add_fact(fact("right", &[string("file1"), string("read")]));
        builder.add_fact(fact("right", &[string("file2"), string("read")]));
        builder.add_fact(fact("right", &[string("file1"), string("write")]));

        let token = builder
            .build_with_rng(&root, SymbolTable::default(), &mut rng)
            .unwrap();
        let base_data = token.to_vec().unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
        token2.to_vec().unwrap()
    };

    let token = Biscuit::from(&data, &root.public()).unwrap();
    let mut verifier = token.authorizer().unwrap();
    verifier.add_fact("resource(\"file1\")");
    verifier.add_fact("operation(\"read\")");
    verifier.allow();
    verifier
        .authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();
    b.bytes = data.len() as u64;
    b.iter(|| {
        let token = Biscuit::from(&data, &root.public()).unwrap();
        let mut verifier = token.authorizer().unwrap();
        verifier.add_fact("resource(\"file1\")");
        verifier.add_fact("operation(\"read\")");
        verifier.allow();
        verifier
            .authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            })
            .unwrap();
    });
}

fn verify_block_5(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let keypair3 = KeyPair::new_with_rng(&mut rng);
    let keypair4 = KeyPair::new_with_rng(&mut rng);
    let keypair5 = KeyPair::new_with_rng(&mut rng);

    let data = {
        let mut builder = Biscuit::builder();
        builder.add_fact(fact("right", &[string("file1"), string("read")]));
        builder.add_fact(fact("right", &[string("file2"), string("read")]));
        builder.add_fact(fact("right", &[string("file1"), string("write")]));

        let token = builder
            .build_with_rng(&root, SymbolTable::default(), &mut rng)
            .unwrap();
        let base_data = token.to_vec().unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token3 = token2
            .append_with_keypair(&keypair3, block_builder)
            .unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token4 = token3
            .append_with_keypair(&keypair4, block_builder)
            .unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token5 = token4
            .append_with_keypair(&keypair5, block_builder)
            .unwrap();
        token5.to_vec().unwrap()
    };

    let token = Biscuit::from(&data, &root.public()).unwrap();
    let mut verifier = token.authorizer().unwrap();
    verifier.add_fact("resource(\"file1\")");
    verifier.add_fact("operation(\"read\")");
    verifier.allow();
    verifier
        .authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();

    b.bytes = data.len() as u64;
    b.iter(|| {
        let token = Biscuit::from(&data, &root.public()).unwrap();
        let mut verifier = token.authorizer().unwrap();
        verifier.add_fact("resource(\"file1\")");
        verifier.add_fact("operation(\"read\")");
        verifier.allow();
        verifier
            .authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            })
            .unwrap();
    });
}

fn check_signature_2(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);

    let data = {
        let mut builder = Biscuit::builder();
        builder.add_fact(fact("right", &[string("file1"), string("read")]));
        builder.add_fact(fact("right", &[string("file2"), string("read")]));
        builder.add_fact(fact("right", &[string("file1"), string("write")]));

        let token = builder
            .build_with_rng(&root, SymbolTable::default(), &mut rng)
            .unwrap();
        let base_data = token.to_vec().unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
        token2.to_vec().unwrap()
    };

    let token = Biscuit::from(&data, &root.public()).unwrap();
    let mut verifier = token.authorizer().unwrap();
    verifier.add_fact("resource(\"file1\")");
    verifier.add_fact("operation(\"read\")");
    verifier.allow();
    verifier
        .authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();

    b.bytes = data.len() as u64;
    b.iter(|| {
        let token = Biscuit::from(&data, &root.public()).unwrap();
    });
}

fn check_signature_5(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let keypair3 = KeyPair::new_with_rng(&mut rng);
    let keypair4 = KeyPair::new_with_rng(&mut rng);
    let keypair5 = KeyPair::new_with_rng(&mut rng);

    let data = {
        let mut builder = Biscuit::builder();
        builder.add_fact(fact("right", &[string("file1"), string("read")]));
        builder.add_fact(fact("right", &[string("file2"), string("read")]));
        builder.add_fact(fact("right", &[string("file1"), string("write")]));

        let token = builder
            .build_with_rng(&root, SymbolTable::default(), &mut rng)
            .unwrap();
        let base_data = token.to_vec().unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token3 = token2
            .append_with_keypair(&keypair3, block_builder)
            .unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token4 = token3
            .append_with_keypair(&keypair4, block_builder)
            .unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token5 = token4
            .append_with_keypair(&keypair5, block_builder)
            .unwrap();
        token5.to_vec().unwrap()
    };

    let token = Biscuit::from(&data, &root.public()).unwrap();
    let mut verifier = token.authorizer().unwrap();
    verifier.add_fact("resource(\"file1\")");
    verifier.add_fact("operation(\"read\")");
    verifier.allow();
    verifier
        .authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();

    b.bytes = data.len() as u64;
    b.iter(|| {
        let token = Biscuit::from(&data, &root.public()).unwrap();
    });
}

fn checks_block_2(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);

    let data = {
        let mut builder = Biscuit::builder();
        builder.add_fact(fact("right", &[string("file1"), string("read")]));
        builder.add_fact(fact("right", &[string("file2"), string("read")]));
        builder.add_fact(fact("right", &[string("file1"), string("write")]));

        let token = builder
            .build_with_rng(&root, SymbolTable::default(), &mut rng)
            .unwrap();
        let base_data = token.to_vec().unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
        token2.to_vec().unwrap()
    };

    let token = Biscuit::from(&data, &root.public()).unwrap();
    let mut verifier = token.authorizer().unwrap();
    verifier.add_fact("resource(\"file1\")");
    verifier.add_fact("operation(\"read\")");
    verifier.allow();
    verifier
        .authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();

    let token = Biscuit::from(&data, &root.public()).unwrap();
    b.bytes = data.len() as u64;
    b.iter(|| {
        let mut verifier = token.authorizer().unwrap();
        verifier.add_fact("resource(\"file1\")");
        verifier.add_fact("operation(\"read\")");
        verifier.allow();
        verifier
            .authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            })
            .unwrap();
    });
}

fn checks_block_create_verifier2(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);

    let data = {
        let mut builder = Biscuit::builder();
        builder.add_fact(fact("right", &[string("file1"), string("read")]));
        builder.add_fact(fact("right", &[string("file2"), string("read")]));
        builder.add_fact(fact("right", &[string("file1"), string("write")]));

        let token = builder
            .build_with_rng(&root, SymbolTable::default(), &mut rng)
            .unwrap();
        let base_data = token.to_vec().unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
        token2.to_vec().unwrap()
    };

    let token = Biscuit::from(&data, &root.public()).unwrap();
    let mut verifier = token.authorizer().unwrap();
    verifier.add_fact("resource(\"file1\")");
    verifier.add_fact("operation(\"read\")");
    verifier.allow();
    verifier
        .authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();

    let token = Biscuit::from(&data, &root.public()).unwrap();
    b.bytes = data.len() as u64;
    b.iter(|| {
        let mut verifier = token.authorizer().unwrap();
    });
}

fn checks_block_verify_only2(b: &mut Bencher) {
    let mut rng: OsRng = OsRng;
    let root = KeyPair::new_with_rng(&mut rng);
    let keypair2 = KeyPair::new_with_rng(&mut rng);

    let data = {
        let mut builder = Biscuit::builder();
        builder.add_fact(fact("right", &[string("file1"), string("read")]));
        builder.add_fact(fact("right", &[string("file2"), string("read")]));
        builder.add_fact(fact("right", &[string("file1"), string("write")]));

        let token = builder
            .build_with_rng(&root, SymbolTable::default(), &mut rng)
            .unwrap();
        let base_data = token.to_vec().unwrap();

        let mut block_builder = BlockBuilder::new();
        block_builder.check_resource("file1");
        block_builder.check_operation("read");

        let token2 = token.append_with_keypair(&keypair2, block_builder).unwrap();
        token2.to_vec().unwrap()
    };

    let token = Biscuit::from(&data, &root.public()).unwrap();
    let mut verifier = token.authorizer().unwrap();
    verifier.add_fact("resource(\"file1\")");
    verifier.add_fact("operation(\"read\")");
    verifier.allow();
    verifier
        .authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();

    let token = Biscuit::from(&data, &root.public()).unwrap();
    b.iter(|| {
        let mut verifier = token.authorizer().unwrap();
        verifier.add_fact("resource(\"file1\")");
        verifier.add_fact("operation(\"read\")");
        verifier.allow();
        verifier
            .authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            })
            .unwrap();
    });
}

benchmark_group!(
    benchmarks,
    create_block_1,
    append_block_2,
    append_block_5,
    unverified_append_block_2,
    unverified_append_block_5,
    verify_block_2,
    verify_block_5,
    check_signature_2,
    check_signature_5,
    checks_block_2,
    checks_block_create_verifier2,
    checks_block_verify_only2
);
benchmark_main!(benchmarks);
