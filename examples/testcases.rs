#![allow(unused_must_use)]
extern crate biscuit_auth as biscuit;

use biscuit::error;
use biscuit::KeyPair;
use biscuit::{builder::*, Biscuit};
use prost::Message;
use rand::prelude::*;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
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

    results.push(scoped_rules(&mut rng, &target, &root, test));

    results.push(scoped_checks(&mut rng, &target, &root, test));

    results.push(expired_token(&mut rng, &target, &root, test));

    results.push(verifier_scope(&mut rng, &target, &root, test));

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

    results.push(sealed_token(&mut rng, &target, &root, test));

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
    pub token: Vec<BlockContent>,
    pub validations: BTreeMap<String, Validation>,
}

#[derive(Debug, Serialize)]
struct BlockContent {
    pub symbols: Vec<String>,
    pub code: String,
}

#[derive(Debug, Serialize)]
struct Validation {
    world: Option<VerifierWorld>,
    result: VerifierResult,
    verifier_code: String,
}

impl TestResult {
    fn print(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();

        writeln!(&mut s, "## {}: {}", self.title, self.filename);

        writeln!(&mut s, "### token\n");
        for (i, block) in self.token.iter().enumerate() {
            if i == 0 {
                writeln!(&mut s, "authority:");
            } else {
                writeln!(&mut s, "{}:", i);
            }

            writeln!(&mut s, "symbols: {:?}\n", block.symbols);
            writeln!(&mut s, "```\n{}```\n", block.code);
        }
        writeln!(&mut s, "```\n");

        for (name, validation) in &self.validations {
            if name.is_empty() {
                writeln!(&mut s, "### validation\n")
            } else {
                writeln!(&mut s, "### validation for \"{}\"\n", name)
            };

            if let Some(world) = &validation.world {
                writeln!(
                    &mut s,
                    "verifier code:\n```\n{}```\n",
                    validation.verifier_code
                );
                writeln!(&mut s, "verifier world:\n```\nWorld {{\n  facts: {:#?}\n  rules: {:#?}\n  checks: {:#?}\n  policies: {:#?}\n}}\n```\n",
                         world.facts, world.rules, world.checks, world.policies);
            }

            writeln!(&mut s, "result: `{:?}`", validation.result);
        }

        s
    }
}

#[derive(Debug, Serialize)]
struct VerifierWorld {
    pub facts: BTreeSet<String>,
    pub rules: BTreeSet<String>,
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
) -> Validation {
    let token = match Biscuit::from(&data[..], |_| root.public()) {
        Ok(t) => t,
        Err(e) => {
            return Validation {
                world: None,
                verifier_code: String::new(),
                result: VerifierResult::Err(vec![format!("{:?}", e)]),
            }
        }
    };

    let mut verifier = match token.verify() {
        Ok(v) => v,
        Err(e) => {
            return Validation {
                world: None,
                verifier_code: String::new(),
                result: VerifierResult::Err(vec![format!("{:?}", e)]),
            }
        }
    };

    let mut verifier_code = String::new();
    for fact in ambient_facts {
        verifier_code += &format!("{};\n", fact);
        verifier.add_fact(fact);
    }

    if !ambient_rules.is_empty() {
        verifier_code += "\n";
    }

    for rule in ambient_rules {
        verifier_code += &format!("{};\n", rule);
        verifier.add_rule(rule);
    }

    if !checks.is_empty() {
        verifier_code += "\n";
    }

    for check in checks {
        verifier.add_check(&check[..]);
        let c: Check = (&check[..]).try_into().unwrap();
        verifier_code += &format!("{};\n", c);
    }

    verifier.allow().unwrap();

    let res = verifier.verify();
    //println!("verifier world:\n{}", verifier.print_world());
    let (mut facts, mut rules, mut checks, mut policies) = verifier.dump();

    Validation {
        world: Some(VerifierWorld {
            facts: facts.drain(..).map(|f| f.to_string()).collect(),
            rules: rules.drain(..).map(|r| r.to_string()).collect(),
            checks: checks.drain(..).map(|c| c.to_string()).collect(),
            policies: policies.drain(..).map(|p| p.to_string()).collect(),
        }),
        result: match res {
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
        verifier_code,
    }
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
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file2"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file1"), s("write")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[var("0")]),
            pred("operation", &[s("read")]),
            pred("right", &[var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test1_basic");
        let t = Biscuit::from(&v[..], |_| root.public()).unwrap();

        let actual = biscuit2.print();
        let expected = t.print();
        print_diff(&actual, &expected);
        v
    } else {
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
            vec![fact("resource", &[string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
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
    let token;

    let root2 = KeyPair::new_with_rng(rng);
    let mut builder = Biscuit::builder(&root2);

    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[var("0")]),
            pred("operation", &[s("read")]),
            pred("right", &[var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test2_different_root_key");
        v
    } else {
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
            vec![fact("resource", &[string("file1")])],
            vec![],
            vec![],
        ),
    );
    TestResult {
        title,
        filename,
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file2"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file1"), s("write")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[var("0")]),
            pred("operation", &[s("read")]),
            pred("right", &[var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test3_invalid_signature_format");
        v
    } else {
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
            vec![fact("resource", &[string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file2"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file1"), s("write")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[var("0")]),
            pred("operation", &[s("read")]),
            pred("right", &[var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test4_random_block");
        v
    } else {
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
            vec![fact("resource", &[string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file2"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file1"), s("write")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[var("0")]),
            pred("operation", &[s("read")]),
            pred("right", &[var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test5_invalid_signature");
        v
    } else {
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
            vec![fact("resource", &[string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file2"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file1"), s("write")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[var("0")]),
            pred("operation", &[s("read")]),
            pred("right", &[var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

    let mut block3 = biscuit2.create_block();

    block3.add_check(rule(
        "check2",
        &[var("0")],
        &[pred("resource", &[string("file1")])],
    ));

    let keypair3 = KeyPair::new_with_rng(rng);
    let biscuit3 = biscuit2.append_with_keypair(&keypair3, block3).unwrap();
    token = print_blocks(&biscuit3);

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
            vec![fact("resource", &[string("file1")])],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn scoped_rules<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "scoped rules".to_string();
    let filename = "test7_scoped_rules.bc".to_string();
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("user_id", &[string("alice")]));
    builder.add_authority_fact(fact("owner", &[string("alice"), string("file1")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_rule(rule(
        "right",
        &[var("0"), s("read")],
        &[
            pred("resource", &[var("0")]),
            pred("user_id", &[var("1")]),
            pred("owner", &[var("1"), var("0")]),
        ],
    ));
    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[var("0")]),
            pred("operation", &[s("read")]),
            pred("right", &[var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

    let mut block3 = biscuit2.create_block();

    block3.add_fact(fact("owner", &[string("alice"), string("file2")]));

    let keypair3 = KeyPair::new_with_rng(rng);
    let biscuit3 = biscuit2.append_with_keypair(&keypair3, block3).unwrap();
    token = print_blocks(&biscuit3);

    let data = if test {
        let v = load_testcase(target, "test7_scoped_rules");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit3.print(), &expected.print());
        v
    } else {
        let data = biscuit3.to_vec().unwrap();
        write_testcase(target, "test7_scoped_rules", &data[..]);

        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[string("file2")]),
                fact("operation", &[s("read")]),
            ],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn scoped_checks<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "scoped checks".to_string();
    let filename = "test8_scoped_checks.bc".to_string();
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[var("0")]),
            pred("operation", &[s("read")]),
            pred("right", &[var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

    let mut block3 = biscuit2.create_block();

    block3.add_fact(fact("right", &[string("file2"), s("read")]));

    let keypair3 = KeyPair::new_with_rng(rng);
    let biscuit3 = biscuit2.append_with_keypair(&keypair3, block3).unwrap();
    token = print_blocks(&biscuit3);

    let data = if test {
        let v = load_testcase(target, "test8_scoped_checks");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit3.print(), &expected.print());
        v
    } else {
        let data = biscuit3.to_vec().unwrap();
        write_testcase(target, "test8_scoped_checks", &data[..]);

        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[string("file2")]),
                fact("operation", &[s("read")]),
            ],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
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
    let token;

    let builder = Biscuit::builder(&root);
    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[string("file1")],
        &[pred("resource", &[string("file1")])],
    ));
    // January 1 2019
    block2.expiration_date(
        UNIX_EPOCH
            .checked_add(Duration::from_secs(49 * 365 * 24 * 3600))
            .unwrap(),
    );

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test9_expired_token");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
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
                fact("resource", &[string("file1")]),
                fact("operation", &[s("read")]),
                fact(
                    "time",
                    &[date(
                        &UNIX_EPOCH
                            .checked_add(Duration::from_secs(1608542592))
                            .unwrap(),
                    )],
                ),
            ],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn verifier_scope<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "verifier scope".to_string();
    let filename = "test10_verifier_scope.bc".to_string();
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_fact(fact("right", &[string("file2"), s("read")]));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test10_verifier_scope");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test10_verifier_scope", &data[..]);

        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[string("file2")]),
                fact("operation", &[s("read")]),
            ],
            vec![],
            vec![vec![rule(
                "check1",
                &[variable("0"), variable("1")],
                &[
                    pred("right", &[var("0"), var("1")]),
                    pred("resource", &[var("0")]),
                    pred("operation", &[var("1")]),
                ],
            )]],
        ),
    );

    TestResult {
        title,
        filename,
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();
    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test11_verifier_authority_caveats");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
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
                fact("resource", &[string("file2")]),
                fact("operation", &[s("read")]),
            ],
            vec![],
            vec![vec![rule(
                "check1",
                &[variable("0"), variable("1")],
                &[
                    pred("right", &[var("0"), var("1")]),
                    pred("resource", &[var("0")]),
                    pred("operation", &[var("1")]),
                ],
            )]],
        ),
    );

    TestResult {
        title,
        filename,
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_check(rule(
        "check1",
        &[string("file1")],
        &[pred("resource", &[string("file1")])],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();
    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test12_authority_caveats");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
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
                fact("resource", &[string("file1")]),
                fact("operation", &[s("read")]),
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
                fact("resource", &[string("file2")]),
                fact("operation", &[s("read")]),
            ],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);
    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file2"), s("read")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    // timestamp for Thursday, December 31, 2030 12:59:59 PM UTC
    let date1 = SystemTime::UNIX_EPOCH + Duration::from_secs(1924952399);

    // generate valid_date("file1") if before date1
    block2.add_rule(constrained_rule(
        "valid_date",
        &[string("file1")],
        &[
            pred("time", &[variable("0")]),
            pred("resource", &[string("file1")]),
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
            pred("time", &[variable("0")]),
            pred("resource", &[variable("1")]),
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
            pred("resource", &[var("0")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test13_block_rules");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
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
                fact("resource", &[string("file1")]),
                fact(
                    "time",
                    &[date(
                        &UNIX_EPOCH
                            .checked_add(Duration::from_secs(1608542592))
                            .unwrap(),
                    )],
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
                fact("resource", &[string("file2")]),
                fact(
                    "time",
                    &[date(
                        &UNIX_EPOCH
                            .checked_add(Duration::from_secs(1608542592))
                            .unwrap(),
                    )],
                ),
            ],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_check(constrained_rule(
        "resource_match",
        &[variable("0")],
        &[pred("resource", &[variable("0")])],
        &[Expression {
            ops: vec![
                Op::Value(var("0")),
                Op::Value(string("file[0-9]+.txt")),
                Op::Binary(Binary::Regex),
            ],
        }],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();
    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test14_regex_constraint");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
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
            vec![fact("resource", &[string("file1")])],
            vec![],
            vec![],
        ),
    );

    validations.insert(
        "file123".to_string(),
        validate_token(
            root,
            &data[..],
            vec![fact("resource", &[string("file123.txt")])],
            vec![],
            vec![],
        ),
    );
    TestResult {
        title,
        filename,
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact(
        "must_be_present",
        &[string("hello")],
        //&[string("hello")],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();
    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test15_multi_queries_caveats");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
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
                    &[pred("must_be_present", &[var("0")])],
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
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_check(rule(
        "check1",
        &[s("test")],
        &[pred("resource", &[s("hello")])],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    //println!("biscuit1 (authority): {}", biscuit1.print());

    let mut block2 = biscuit1.create_block();
    block2.add_fact(fact("check1", &[s("test")])).unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test16_caveat_head_name");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
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
        token,
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
    let token;

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

    //bytes equal
    builder.add_authority_check("check if hex:12ab == hex:12ab");

    // set contains
    builder.add_authority_check("check if [1, 2].contains(2)");
    builder.add_authority_check("check if [2020-12-04T09:46:41+00:00, 2019-12-04T09:46:41+00:00].contains(2020-12-04T09:46:41+00:00)");
    builder.add_authority_check("check if [true, false, true].contains(true)");
    builder.add_authority_check("check if [\"abc\", \"def\"].contains(\"abc\")");
    builder.add_authority_check("check if [hex:12ab, hex:34de].contains(hex:34de)");

    let biscuit = builder.build_with_rng(rng).unwrap();
    token = print_blocks(&biscuit);

    let data = if test {
        let v = load_testcase(target, "test17_expressions");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit.print(), &expected.print());
        v
    } else {
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
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);
    builder.add_authority_check(rule(
        "check1",
        &[s("test")],
        &[pred("operation", &[s("read")])],
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
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test8_invalid_block_fact_ambient");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
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
            vec![fact("operation", &[s("write")])],
            vec![],
            vec![],
        ),
    );
    TestResult {
        title,
        filename,
        token,
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
    let token;

    let mut builder = Biscuit::builder(&root);
    builder.add_authority_check(rule(
        "check1",
        &[s("test")],
        &[pred("operation", &[s("read")])],
    ));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2
        .add_rule(rule(
            "operation",
            &[s("read")],
            &[pred("operation", &[var("any")])],
        ))
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test19_generating_ambient_from_variables");
        let expected = Biscuit::from(&v[..], |_| root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
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
            vec![fact("operation", &[s("write")])],
            vec![],
            vec![],
        ),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn sealed_token<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "sealed token".to_string();
    let filename = "test20_sealed.bc".to_string();
    let token;

    let mut builder = Biscuit::builder(&root);

    builder.add_authority_fact(fact("right", &[string("file1"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file2"), s("read")]));
    builder.add_authority_fact(fact("right", &[string("file1"), s("write")]));

    let biscuit1 = builder.build_with_rng(rng).unwrap();

    let mut block2 = biscuit1.create_block();

    block2.add_check(rule(
        "check1",
        &[var("0")],
        &[
            pred("resource", &[var("0")]),
            pred("operation", &[s("read")]),
            pred("right", &[var("0"), s("read")]),
        ],
    ));

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test20_sealed");
        let t = Biscuit::from(&v[..], |_| root.public()).unwrap();

        let actual = biscuit2.print();
        let expected = t.print();
        print_diff(&actual, &expected);
        v
    } else {
        let data = biscuit2.seal().unwrap();
        write_testcase(target, "test20_sealed", &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            vec![
                fact("resource", &[string("file1")]),
                fact("operation", &[string("read")]),
            ],
            vec![],
            vec![],
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn print_blocks(token: &Biscuit) -> Vec<BlockContent> {
    let mut v = Vec::new();

    for i in 0..token.block_count() {
        v.push(BlockContent {
            symbols: token.block_symbols(i).unwrap(),
            code: token.print_block_source(i).unwrap(),
        });
    }

    v
}
