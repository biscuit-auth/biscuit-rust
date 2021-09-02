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
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Write,
    time::*,
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

    let mut test = false;
    let mut json = false;
    match args.next().as_deref() {
        Some("--test") => test = true,
        Some("--json") => json = true,
        Some(arg) => {
            println!("unknown argument: {}", arg);
            return;
        }
        None => {}
    };

    match args.next().as_deref() {
        Some("--test") => test = true,
        Some("--json") => json = true,
        Some(arg) => {
            println!("unknown argument: {}", arg);
            return;
        }
        None => {}
    };

    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let root = KeyPair::new_with_rng(&mut rng);

    let mut results = Vec::new();
    results.push(basic_token(&mut rng, &target, &root, test));

    results.push(different_root_key(&mut rng, &target, &root, test));

    results.push(invalid_signature_format(&mut rng, &target, &root, test));

    results.push(random_block(&mut rng, &target, &root, test));

    results.push(invalid_signature(&mut rng, &target, &root, test));

    results.push(reordered_blocks(&mut rng, &target, &root, test));

    results.push(invalid_block_fact_authority(&mut rng, &target, &root, test));

    results.push(invalid_block_fact_ambient(&mut rng, &target, &root, test));

    results.push(expired_token(&mut rng, &target, &root, test));

    results.push(authority_rules(&mut rng, &target, &root, test));

    results.push(verifier_authority_checks(&mut rng, &target, &root, test));

    results.push(authority_checks(&mut rng, &target, &root, test));

    results.push(block_rules(&mut rng, &target, &root, test));

    results.push(regex_constraint(&mut rng, &target, &root, test));

    results.push(multi_queries_checks(&mut rng, &target, &root, test));

    results.push(check_head_name(&mut rng, &target, &root, test));

    results.push(expressions(&mut rng, &target, &root, test));

    results.push(unbound_variables_in_rule(&mut rng, &target, &root, test));

    results.push(generating_ambient_from_variables(
        &mut rng, &target, &root, test,
    ));

    if json {
        let s = serde_json::to_string_pretty(&TestCases {
            root_private_key: hex::encode(root.private().to_bytes()),
            root_public_key: hex::encode(root.public().to_bytes()),
            testcases: results,
        })
        .unwrap();

        println!("{}", s);
    } else {
        println!("# Biscuit samples and expected results\n");
        println!(
            "root secret key: {}",
            hex::encode(root.private().to_bytes())
        );
        println!("root public key: {}", hex::encode(root.public().to_bytes()));

        for result in results {
            println!("\n------------------------------\n");
            println!("{}", result.print());
        }
    }
}

#[derive(Debug, Serialize)]
struct TestCases {
    pub root_private_key: String,
    pub root_public_key: String,
    pub testcases: Vec<TestResult>,
}
#[derive(Debug, Serialize)]
struct TestResult {
    pub title: String,
    pub filename: String,
    pub print_token: BTreeMap<String, String>,
    pub validations: BTreeMap<String, (Option<VerifierWorld>, VerifierResult)>,
}

impl TestResult {
    fn print(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();

        writeln!(&mut s, "## {}: {}", self.title, self.filename);

        for (title, token) in &self.print_token {
            writeln!(&mut s, "{}:\n```\n{}\n```\n", title, token);
        }

        for (name, (verifier_world, verifier_result)) in &self.validations {
            if name.is_empty() {
                writeln!(&mut s, "validation:")
            } else {
                writeln!(&mut s, "validation for \"{}\":", name)
            };

            if let Some(world) = verifier_world {
                writeln!(&mut s, "verifier world:\nWorld {{\n  facts: {:#?}\n  privileged rules: {:#?}\n  rules: {:#?}\n  checks: {:#?}\n  policies: {:#?}\n}}\n",
                         world.facts, world.privileged_rules, world.rules, world.checks, world.policies);
            }

            writeln!(&mut s, "{:?}", verifier_result);
        }

        s
    }
}

#[derive(Debug, Serialize)]
struct VerifierWorld {
    pub facts: BTreeSet<String>,
    pub rules: BTreeSet<String>,
    pub privileged_rules: BTreeSet<String>,
    pub checks: BTreeSet<String>,
    pub policies: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
enum VerifierResult {
    Ok(usize),
    Err(Vec<String>),
}

fn validate_token(
    root: &KeyPair,
    data: &[u8],
    ambient_facts: Vec<Fact>,
    ambient_rules: Vec<Rule>,
    checks: Vec<Vec<Rule>>,
) -> (Option<VerifierWorld>, VerifierResult) {
    let token = match Biscuit::from(&data[..], |_| root.public()) {
        Ok(t) => t,
        Err(e) => return (None, VerifierResult::Err(vec![format!("{:?}", e)])),
    };

    let mut verifier = match token.verify() {
        Ok(v) => v,
        Err(e) => return (None, VerifierResult::Err(vec![format!("{:?}", e)])),
    };

    for fact in ambient_facts {
        verifier.add_fact(fact);
    }
    for rule in ambient_rules {
        verifier.add_rule(rule);
    }
    for check in checks {
        verifier.add_check(&check[..]);
    }

    verifier.allow().unwrap();

    let res = verifier.verify();
    //println!("verifier world:\n{}", verifier.print_world());
    let (mut facts, mut rules, mut privileged_rules, mut checks, mut policies) = verifier.dump();
    (
        Some(VerifierWorld {
            facts: facts.drain(..).map(|f| f.to_string()).collect(),
            rules: rules.drain(..).map(|r| r.to_string()).collect(),
            privileged_rules: privileged_rules.drain(..).map(|r| r.to_string()).collect(),
            checks: checks.drain(..).map(|c| c.to_string()).collect(),
            policies: policies.drain(..).map(|p| p.to_string()).collect(),
        }),
        match res {
            Ok(i) => VerifierResult::Ok(i),
            Err(e) => {
                if let error::Token::FailedLogic(error::Logic::FailedChecks(mut v)) = e {
                    VerifierResult::Err(v.drain(..).map(|e| format!("{:?}", e)).collect())
                } else {
                    let s = format!("{:?}", e);
                    VerifierResult::Err(vec![s])
                }
            }
        },
    )
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

fn basic_token<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "basic token".to_string();
    let filename = "test1_basic.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")]));
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
        let token = Biscuit::from(&v[..], |_| root.public()).unwrap();

        let actual = biscuit2.print();
        let expected = token.print();
        print_diff(&actual, &expected);
        v
    } else {
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test1_basic", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn different_root_key<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "different root key".to_string();
    let filename = "test2_different_root_key.bc".to_string();
    let mut print_token = BTreeMap::new();

    let root2 = KeyPair::new_with_rng(rng);
    let mut builder = Biscuit::builder(&root2);

    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")]));

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
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test2_different_root_key", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
        ),
    );
    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn invalid_signature_format<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "invalid signature format".to_string();
    let filename = "test3_invalid_signature_format.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")]));
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
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let serialized = biscuit2.container().unwrap();
        let mut proto = serialized.to_proto();
        proto.authority.signature.truncate(16);
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();
        write_testcase(target, "test3_invalid_signature_format", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn random_block<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "random block".to_string();
    let filename = "test4_random_block.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")]));
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
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let serialized = biscuit2.container().unwrap();
        let mut proto = serialized.to_proto();
        let arr: [u8; 32] = rng.gen();
        proto.blocks[0].block = Vec::from(&arr[..]);
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();

        write_testcase(target, "test4_random_block", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn invalid_signature<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "invalid signature".to_string();
    let filename = "test5_invalid_signature.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")]));
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
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let serialized = biscuit2.container().unwrap();
        let mut proto = serialized.to_proto();
        proto.authority.signature[0] = proto.authority.signature[0] + 1;
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();

        write_testcase(target, "test5_invalid_signature", &data[..]);

        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn reordered_blocks<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "reordered blocks".to_string();
    let filename = "test6_reordered_blocks.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")]));
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

    print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

    let mut block3 = biscuit2.create_block();

    block3.add_check(rule(
        "check2",
        &[var("0")],
        &[pred("resource", &[s("ambient"), string("file1")])],
    ));

    let keypair3 = KeyPair::new_with_rng(rng);
    let biscuit3 = biscuit2.append_with_rng(rng, &keypair3, block3).unwrap();
    print_token.insert("biscuit3 (2 checks)".to_string(), biscuit3.print());

    let mut serialized = biscuit3.container().unwrap().clone();
    let mut blocks = vec![];
    blocks.push(serialized.blocks[1].clone());
    blocks.push(serialized.blocks[0].clone());
    serialized.blocks = blocks;

    let data = if test {
        let v = load_testcase(target, "test6_reordered_blocks");
        v
    } else {
        let data = serialized.to_vec().unwrap();
        write_testcase(target, "test6_reordered_blocks", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn invalid_block_fact_authority<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "invalid block fact with authority tag".to_string();
    let filename = "test7_invalid_block_fact_authority.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")]));

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
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test7_invalid_block_fact_authority", &data[..]);

        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn invalid_block_fact_ambient<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "invalid block fact with ambient tag".to_string();
    let filename = "test8_invalid_block_fact_ambient.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")]));

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
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test8_invalid_block_fact_ambient", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn expired_token<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "expired token".to_string();
    let filename = "test9_expired_token.bc".to_string();
    let mut print_token = BTreeMap::new();

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
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test9_expired_token", &data[..]);

        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
                fact("operation", &[s("ambient"), s("read")]),
                fact(
                    "time",
                    &[
                        s("ambient"),
                        date(
                            &UNIX_EPOCH
                                .checked_add(Duration::from_secs(1608542592))
                                .unwrap(),
                        ),
                    ],
                ),
            ],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn authority_rules<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "authority rules".to_string();
    let filename = "test10_authority_rules.bc".to_string();
    let mut print_token = BTreeMap::new();

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
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test10_authority_rules", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
                fact("operation", &[s("ambient"), s("read")]),
                fact("owner", &[s("ambient"), s("alice"), string("file1")]),
            ],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn verifier_authority_checks<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "verifier authority checks".to_string();
    let filename = "test11_verifier_authority_caveats.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let data = if test {
        let v = load_testcase(target, "test11_verifier_authority_caveats");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit".to_string(), biscuit1.print());

        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test11_verifier_authority_caveats", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
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
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn authority_checks<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "authority checks".to_string();
    let filename = "test12_authority_caveats.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_check(rule(
        "check1",
        &[string("file1")],
        &[pred("resource", &[s("ambient"), string("file1")])],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let data = if test {
        let v = load_testcase(target, "test12_authority_caveats");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit".to_string(), biscuit1.print());

        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test12_authority_caveats", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "file1".to_string(),
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
                fact("operation", &[s("ambient"), s("read")]),
            ],
            vec![],
            vec![],
        ),
    );

    validations.insert(
        "file2".to_string(),
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file2")]),
                fact("operation", &[s("ambient"), s("read")]),
            ],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn block_rules<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "block rules".to_string();
    let filename = "test13_block_rules.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact("right", &[s("authority"), string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[s("authority"), string("file2"), s("read")]));

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
        &[Expression {
            ops: vec![
                Op::Value(var("0")),
                Op::Value(date(&date1)),
                Op::Binary(Binary::LessOrEqual),
            ],
        }],
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
            Expression {
                ops: vec![
                    Op::Value(var("0")),
                    Op::Value(date(&date2)),
                    Op::Binary(Binary::LessOrEqual),
                ],
            },
            Expression {
                ops: vec![
                    Op::Value(set(strings)),
                    Op::Value(var("1")),
                    Op::Binary(Binary::Contains),
                    Op::Unary(Unary::Negate),
                ],
            },
        ],
    ));

    block2.add_check(rule(
        "check1",
        &[variable("0")],
        &[
            pred("valid_date", &[variable("0")]),
            pred("resource", &[s("ambient"), var("0")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test13_block_rules");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test13_block_rules", &data[..]);

        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "file1".to_string(),
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file1")]),
                fact(
                    "time",
                    &[
                        s("ambient"),
                        date(
                            &UNIX_EPOCH
                                .checked_add(Duration::from_secs(1608542592))
                                .unwrap(),
                        ),
                    ],
                ),
            ],
            vec![],
            vec![],
        ),
    );

    validations.insert(
        "file2".to_string(),
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[s("ambient"), string("file2")]),
                fact(
                    "time",
                    &[
                        s("ambient"),
                        date(
                            &UNIX_EPOCH
                                .checked_add(Duration::from_secs(1608542592))
                                .unwrap(),
                        ),
                    ],
                ),
            ],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn regex_constraint<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "regex_constraint".to_string();
    let filename = "test14_regex_constraint.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_check(constrained_rule(
        "resource_match",
        &[variable("0")],
        &[pred("resource", &[s("ambient"), variable("0")])],
        &[Expression {
            ops: vec![
                Op::Value(var("0")),
                Op::Value(string("file[0-9]+.txt")),
                Op::Binary(Binary::Regex),
            ],
        }],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let data = if test {
        let v = load_testcase(target, "test14_regex_constraint");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit".to_string(), biscuit1.print());

        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test14_regex_constraint", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "file1".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file1")])],
            vec![],
            vec![],
        ),
    );

    validations.insert(
        "file123".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[s("ambient"), string("file123.txt")])],
            vec![],
            vec![],
        ),
    );
    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn multi_queries_checks<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "multi queries checks".to_string();
    let filename = "test15_multi_queries_caveats.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact(
        "must_be_present",
        &[s("authority"), string("hello")],
        //&[string("hello")],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let data = if test {
        let v = load_testcase(target, "test15_multi_queries_caveats");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit".to_string(), biscuit1.print());

        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test15_multi_queries_caveats", &data[..]);

        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![],
            vec![],
            vec![vec![
                rule(
                    "test_must_be_present_authority",
                    &[variable("0")],
                    &[pred("must_be_present", &[s("authority"), var("0")])],
                ),
                rule(
                    "test_must_be_present",
                    &[variable("0")],
                    &[pred("must_be_present", &[var("0")])],
                ),
            ]],
        ),
    );
    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn check_head_name<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "check head name should be independent from fact names".to_string();
    let filename = "test16_caveat_head_name.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_check(rule(
        "check1",
        &[s("test")],
        &[pred("resource", &[s("ambient"), s("hello")])],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    //println!("biscuit1 (authority): {}", biscuit1.print());

    let mut block2 = biscuit1.create_block();
    block2.add_fact(fact("check1", &[s("test")])).unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test16_caveat_head_name");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit".to_string(), biscuit2.print());
        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test16_caveat_head_name", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], vec![], vec![], vec![]),
    );
    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn expressions<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "test expression syntax and all available operations".to_string();
    let filename = "test17_expressions.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);

    //boolean true
    builder.add_authority_check("check if true");
    //boolean false and negation
    builder.add_authority_check("check if !false");
    //boolean and
    builder.add_authority_check("check if !false and true");
    //boolean or
    builder.add_authority_check("check if false or true");
    //boolean parens
    builder.add_authority_check("check if (true or false) and true");

    //integer less than
    builder.add_authority_check("check if 1 < 2");
    //integer greater than
    builder.add_authority_check("check if 2 > 1");
    //integer less or equal
    builder.add_authority_check("check if 1 <= 2");
    builder.add_authority_check("check if 1 <= 1");
    //integer greater or equal
    builder.add_authority_check("check if 2 >= 1");
    builder.add_authority_check("check if 2 >= 2");
    //integer equal
    builder.add_authority_check("check if 3 == 3");
    //integer add sub mul div
    builder.add_authority_check("check if 1 + 2 * 3 - 4 /2 == 5");

    // string prefix and suffix
    builder.add_authority_check(
        "check if \"hello world\".starts_with(\"hello\") && \"hello world\".ends_with(\"world\")",
    );
    // string regex
    builder.add_authority_check("check if \"aaabde\".matches(\"a*c?.e\")");
    // string equal
    builder.add_authority_check("check if \"abcD12\" == \"abcD12\"");

    //date less than
    builder.add_authority_check("check if 2019-12-04T09:46:41+00:00 < 2020-12-04T09:46:41+00:00");
    //date greater than
    builder.add_authority_check("check if 2020-12-04T09:46:41+00:00 > 2019-12-04T09:46:41+00:00");
    //date less or equal
    builder.add_authority_check("check if 2019-12-04T09:46:41+00:00 <= 2020-12-04T09:46:41+00:00");
    builder.add_authority_check("check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00");
    //date greater or equal
    builder.add_authority_check("check if 2020-12-04T09:46:41+00:00 >= 2019-12-04T09:46:41+00:00");
    builder.add_authority_check("check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00");
    //date equal
    builder.add_authority_check("check if 2020-12-04T09:46:41+00:00 == 2020-12-04T09:46:41+00:00");

    //symbol equal
    builder.add_authority_check("check if #abc == #abc");

    //bytes equal
    builder.add_authority_check("check if hex:12ab == hex:12ab");

    // set contains
    builder.add_authority_check("check if [1, 2].contains(2)");
    builder.add_authority_check("check if [2020-12-04T09:46:41+00:00, 2019-12-04T09:46:41+00:00].contains(2020-12-04T09:46:41+00:00)");
    builder.add_authority_check("check if [true, false, true].contains(true)");
    builder.add_authority_check("check if [\"abc\", \"def\"].contains(\"abc\")");
    builder.add_authority_check("check if [hex:12ab, hex:34de].contains(hex:34de)");
    builder.add_authority_check("check if [#hello, #world].contains(#hello)");

    let biscuit = builder.build_with_rng(rng).unwrap();

    let data = if test {
        let v = load_testcase(target, "test17_expressions");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit".to_string(), biscuit.print());
        let data = biscuit.to_vec().unwrap();
        write_testcase(target, "test17_expressions", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], vec![], vec![], vec![]),
    );

    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn unbound_variables_in_rule<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "invalid block rule with unbound_variables".to_string();
    let filename = "test18_unbound_variables_in_rule.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);
    builder.add_authority_check(rule(
        "check1",
        &[s("test")],
        &[pred("operation", &[s("ambient"), s("read")])],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2
        .add_rule(rule(
            "operation",
            &[var("unbound"), s("read")],
            &[pred("operation", &[var("any1"), var("any2")])],
        ))
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test8_invalid_block_fact_ambient");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test18_unbound_variables_in_rule", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("operation", &[s("ambient"), s("write")])],
            vec![],
            vec![],
        ),
    );
    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}

fn generating_ambient_from_variables<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "invalid block rule generating an #authority or #ambient symbol with a variable"
        .to_string();
    let filename = "test19_generating_ambient_from_variables.bc".to_string();
    let mut print_token = BTreeMap::new();

    let mut builder = Biscuit::builder(&root);
    builder.add_authority_check(rule(
        "check1",
        &[s("test")],
        &[pred("operation", &[s("ambient"), s("read")])],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2
        .add_rule(rule(
            "operation",
            &[var("ambient"), s("read")],
            &[pred("operation", &[var("ambient"), var("any")])],
        ))
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_rng(rng, &keypair2, block2).unwrap();

    let data = if test {
        let v = load_testcase(target, "test19_generating_ambient_from_variables");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        print_token.insert("biscuit2 (1 check)".to_string(), biscuit2.print());

        let data = biscuit2.to_vec().unwrap();
        write_testcase(
            target,
            "test19_generating_ambient_from_variables",
            &data[..],
        );
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("operation", &[s("ambient"), s("write")])],
            vec![],
            vec![],
        ),
    );
    TestResult {
        title,
        filename,
        print_token,
        validations,
    }
}
