#![cfg(feature = "serde-error")]
#![allow(unused_must_use)]
extern crate biscuit_auth as biscuit;

use biscuit::builder::BlockBuilder;
use biscuit::datalog::SymbolTable;
use biscuit::error;
use biscuit::format::convert::v2 as convert;
use biscuit::macros::*;
use biscuit::Authorizer;
use biscuit::{builder::*, builder_ext::*, Biscuit};
use biscuit::{KeyPair, PrivateKey, PublicKey};
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
    let mut root_key = None;

    match args.next().as_deref() {
        Some("--test") => test = true,
        Some("--json") => json = true,
        Some("--key") => root_key = args.next(),
        Some(arg) => {
            println!("unknown argument: {}", arg);
            return;
        }
        None => {}
    };

    match args.next().as_deref() {
        Some("--test") => test = true,
        Some("--json") => json = true,
        Some("--key") => root_key = args.next(),
        Some(arg) => {
            println!("unknown argument: {}", arg);
            return;
        }
        None => {}
    };

    match args.next().as_deref() {
        Some("--test") => test = true,
        Some("--json") => json = true,
        Some("--key") => root_key = args.next(),
        Some(arg) => {
            println!("unknown argument: {}", arg);
            return;
        }
        None => {}
    };

    if let Some(key) = root_key {
        root = KeyPair::from(&PrivateKey::from_bytes_hex(&key).unwrap());
    } else {
        let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
        KeyPair::new_with_rng(&mut rng)
    };

    let mut results = Vec::new();
    add_test_result(&mut results, basic_token(&target, &root, test));

    add_test_result(&mut results, different_root_key(&target, &root, test));

    add_test_result(&mut results, invalid_signature_format(&target, &root, test));

    add_test_result(&mut results, random_block(&target, &root, test));

    add_test_result(&mut results, invalid_signature(&target, &root, test));

    add_test_result(&mut results, reordered_blocks(&target, &root, test));

    add_test_result(&mut results, scoped_rules(&target, &root, test));

    add_test_result(&mut results, scoped_checks(&target, &root, test));

    add_test_result(&mut results, expired_token(&target, &root, test));

    add_test_result(&mut results, authorizer_scope(&target, &root, test));

    add_test_result(
        &mut results,
        authorizer_authority_checks(&target, &root, test),
    );

    add_test_result(&mut results, authority_checks(&target, &root, test));

    add_test_result(&mut results, block_rules(&target, &root, test));

    add_test_result(&mut results, regex_constraint(&target, &root, test));

    add_test_result(&mut results, multi_queries_checks(&target, &root, test));

    add_test_result(&mut results, check_head_name(&target, &root, test));

    add_test_result(&mut results, expressions(&target, &root, test));

    add_test_result(
        &mut results,
        unbound_variables_in_rule(&target, &root, test),
    );

    add_test_result(
        &mut results,
        generating_ambient_from_variables(&target, &root, test),
    );

    add_test_result(&mut results, sealed_token(&target, &root, test));

    add_test_result(&mut results, parsing(&target, &root, test));

    add_test_result(&mut results, default_symbols(&target, &root, test));

    add_test_result(&mut results, execution_scope(&target, &root, test));

    add_test_result(&mut results, third_party(&target, &root, test));

    add_test_result(&mut results, check_all(&target, &root, test));

    add_test_result(&mut results, public_keys_interning(&target, &root, test));

    add_test_result(&mut results, integer_wraparound(&target, &root, test));

    add_test_result(&mut results, expressions_v4(&target, &root, test));

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
    pub public_keys: Vec<String>,
    pub external_key: Option<String>,
    pub code: String,
}

#[derive(Debug, Serialize)]
struct Validation {
    world: Option<AuthorizerWorld>,
    result: AuthorizerResult,
    authorizer_code: String,
    revocation_ids: Vec<String>,
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
            writeln!(&mut s, "public keys: {:?}\n", block.public_keys);
            if let Some(key) = &block.external_key {
                writeln!(&mut s, "external signature by: {:?}\n", key);
            }
            writeln!(&mut s, "```\n{}```\n", block.code);
        }

        for (name, validation) in &self.validations {
            if name.is_empty() {
                writeln!(&mut s, "### validation\n")
            } else {
                writeln!(&mut s, "### validation for \"{}\"\n", name)
            };

            if let Some(world) = &validation.world {
                writeln!(
                    &mut s,
                    "authorizer code:\n```\n{}```\n",
                    validation.authorizer_code
                );

                writeln!(&mut s, "revocation ids:");
                for id in &validation.revocation_ids {
                    writeln!(&mut s, "- `{}`", id);
                }
                writeln!(&mut s, "\nauthorizer world:\n```\nWorld {{\n  facts: {:#?}\n  rules: {:#?}\n  checks: {:#?}\n  policies: {:#?}\n}}\n```\n",
                         world.facts, world.rules, world.checks, world.policies);
            }

            writeln!(&mut s, "result: `{:?}`", validation.result);
        }

        s
    }
}

#[derive(Debug, Serialize)]
struct AuthorizerWorld {
    pub facts: BTreeSet<(String, BTreeSet<Option<usize>>)>,
    pub rules: BTreeSet<(String, Option<usize>)>,
    pub checks: BTreeSet<String>,
    pub policies: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
enum AuthorizerResult {
    Ok(usize),
    Err(error::Token),
}

fn validate_token(root: &KeyPair, data: &[u8], authorizer_code: &str) -> Validation {
    let token = match Biscuit::from(&data[..], &root.public()) {
        Ok(t) => t,
        Err(e) => {
            return Validation {
                world: None,
                authorizer_code: String::new(),
                result: AuthorizerResult::Err(e),
                revocation_ids: vec![],
            }
        }
    };

    let mut revocation_ids = vec![];

    for bytes in token.revocation_identifiers() {
        revocation_ids.push(hex::encode(&bytes));
    }

    let mut authorizer = Authorizer::new();
    authorizer.add_code(authorizer_code).unwrap();
    let authorizer_code = authorizer.dump_code();

    match authorizer.add_token(&token) {
        Ok(v) => v,
        Err(e) => {
            return Validation {
                world: None,
                authorizer_code: String::new(),
                result: AuthorizerResult::Err(e),
                revocation_ids,
            }
        }
    };

    let res = authorizer.authorize();
    //println!("authorizer world:\n{}", authorizer.print_world());
    let (_, _, mut checks, mut policies) = authorizer.dump();
    let snapshot = authorizer.snapshot().unwrap();

    let symbols = SymbolTable::from_symbols_and_public_keys(
        snapshot.world.symbols,
        snapshot
            .world
            .public_keys
            .iter()
            .map(|k| PublicKey::from_proto(k).unwrap())
            .collect(),
    )
    .unwrap();

    let mut facts = BTreeSet::new();
    let mut rules = BTreeSet::new();
    for (i, block) in snapshot.world.blocks.iter().enumerate() {
        let mut origin = BTreeSet::new();
        origin.insert(i);
        for rule in block.rules_v2.iter() {
            let r =
                convert::proto_rule_to_token_rule(&rule, snapshot.world.version.unwrap()).unwrap();
            rules.insert((symbols.print_rule(&r.0), Some(i)));
        }
    }

    let mut authorizer_origin = BTreeSet::new();
    authorizer_origin.insert(usize::MAX);
    for rule in snapshot.world.authorizer_block.rules_v2 {
        let r = convert::proto_rule_to_token_rule(&rule, snapshot.world.version.unwrap()).unwrap();
        rules.insert((symbols.print_rule(&r.0), None));
    }

    for factset in snapshot.world.generated_facts {
        use biscuit_auth::format::schema::origin::Content;
        let mut origin = BTreeSet::new();

        for o in factset.origins {
            match o.content.unwrap() {
                Content::Authorizer(_) => origin.insert(None),
                Content::Origin(i) => origin.insert(Some(i as usize)),
            };
        }

        for fact in factset.facts {
            let f = convert::proto_fact_to_token_fact(&fact).unwrap();
            facts.insert((symbols.print_fact(&f), origin.clone()));
        }
    }

    Validation {
        world: Some(AuthorizerWorld {
            facts,
            rules,
            checks: checks.drain(..).map(|c| c.to_string()).collect(),
            policies: policies.drain(..).map(|p| p.to_string()).collect(),
        }),
        result: match res {
            Ok(i) => AuthorizerResult::Ok(i),
            Err(e) => AuthorizerResult::Err(e),
        },
        authorizer_code,
        revocation_ids,
    }
}

fn add_test_result(results: &mut Vec<TestResult>, mut testcase: TestResult) {
    testcase.filename = format!("{}.bc", testcase.filename);
    results.push(testcase);
}

fn write_testcase(target: &str, name: &str, data: &[u8]) {
    //println!("written to: {}/{}", target, name);

    let mut file = File::create(&format!("{}/{}.bc", target, name)).unwrap();
    file.write_all(data).unwrap();
    file.flush().unwrap();
}

#[track_caller]
fn load_testcase(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(&format!("{}/{}.bc", target, name)).unwrap()
}

fn print_diff(actual: &str, expected: &str) {
    if actual != expected {
        println!("{}", colored_diff::PrettyDifference { expected, actual })
    }
}

fn write_or_load_testcase(
    target: &str,
    filename: &str,
    root: &KeyPair,
    token: &Biscuit,
    test: bool,
) -> Vec<u8> {
    if test {
        let v = load_testcase(target, &filename);
        if let Ok(expected) = Biscuit::from(&v[..], root.public()) {
            print_diff(&token.print(), &expected.print());
        }
        v
    } else {
        let data = token.to_vec().unwrap();
        write_testcase(target, &filename, &data[..]);

        data
    }
}

fn basic_token(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "basic token".to_string();
    let filename = "test001_basic".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(
                r#"
            check if resource($0), operation("read"), right($0, "read")
            "#
            ),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
            resource("file1");
            allow if true;
        "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn different_root_key(target: &str, root: &KeyPair, test: bool) -> TestResult {
    // using a different seed otherwise it would generate the same root key
    let mut rng: StdRng = SeedableRng::seed_from_u64(5678);
    let title = "different root key".to_string();
    let filename = "test002_different_root_key".to_string();
    let token;

    let root2 = KeyPair::new_with_rng(&mut rng);

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root2, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(
                r#"
                check if resource($0), operation("read"), right($0, "read")
            "#
            ),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
        resource("file1");
        allow if true;
        "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn invalid_signature_format(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "invalid signature format".to_string();
    let filename = "test003_invalid_signature_format".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, &filename);
        v
    } else {
        let serialized = biscuit2.container();
        let mut proto = serialized.to_proto();
        proto.authority.signature.truncate(16);
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();
        write_testcase(target, &filename, &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn random_block(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "random block".to_string();
    let filename = "test004_random_block".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, &filename);
        v
    } else {
        let serialized = biscuit2.container();
        let mut proto = serialized.to_proto();
        let arr: [u8; 32] = rng.gen();
        proto.blocks[0].block = Vec::from(&arr[..]);
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();

        write_testcase(target, &filename, &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn invalid_signature(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "invalid signature".to_string();
    let filename = "test005_invalid_signature".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, &filename);
        v
    } else {
        let serialized = biscuit2.container();
        let mut proto = serialized.to_proto();
        proto.authority.signature[0] = proto.authority.signature[0] + 1;
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();

        write_testcase(target, &filename, &data[..]);

        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn reordered_blocks(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "reordered blocks".to_string();
    let filename = "test006_reordered_blocks".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    let keypair3 = KeyPair::new_with_rng(&mut rng);
    let biscuit3 = biscuit2
        .append_with_keypair(&keypair3, block!(r#"check if resource("file1")"#))
        .unwrap();
    token = print_blocks(&biscuit3);

    let mut serialized = biscuit3.container().clone();
    let mut blocks = vec![];
    blocks.push(serialized.blocks[1].clone());
    blocks.push(serialized.blocks[0].clone());
    serialized.blocks = blocks;

    let data = if test {
        let v = load_testcase(target, &filename);
        v
    } else {
        let data = serialized.to_vec().unwrap();
        write_testcase(target, &filename, &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn scoped_rules(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "scoped rules".to_string();
    let filename = "test007_scoped_rules".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        user_id("alice");
        owner("alice", "file1");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(
                r#"
            right($0, "read") <- resource($0), user_id($1), owner($1, $0);
            check if resource($0), operation("read"), right($0, "read");
        "#
            ),
        )
        .unwrap();

    let mut block3 = BlockBuilder::new();

    block3.add_fact(r#"owner("alice", "file2")"#).unwrap();

    let keypair3 = KeyPair::new_with_rng(&mut rng);
    let biscuit3 = biscuit2.append_with_keypair(&keypair3, block3).unwrap();
    token = print_blocks(&biscuit3);

    let data = write_or_load_testcase(target, &filename, root, &biscuit3, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                operation("read");
                allow if true;
                "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn scoped_checks(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "scoped checks".to_string();
    let filename = "test008_scoped_checks".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    let keypair3 = KeyPair::new_with_rng(&mut rng);
    let biscuit3 = biscuit2
        .append_with_keypair(&keypair3, block!(r#"right("file2", "read")"#))
        .unwrap();
    token = print_blocks(&biscuit3);

    let data = write_or_load_testcase(target, &filename, root, &biscuit3, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                operation("read");
                allow if true;
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn expired_token(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "expired token".to_string();
    let filename = "test009_expired_token".to_string();
    let token;

    let builder = Biscuit::builder();
    let biscuit1 = builder
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();

    let mut block2 = block!(r#"check if resource("file1");"#);

    // January 1 2019
    block2.check_expiration_date(
        UNIX_EPOCH
            .checked_add(Duration::from_secs(49 * 365 * 24 * 3600))
            .unwrap(),
    );

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file1");
                operation("read");
                time(2020-12-21T09:23:12Z);
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn authorizer_scope(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "authorizer scope".to_string();
    let filename = "test010_authorizer_scope".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!(r#"right("file2", "read")"#))
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                operation("read");
                check if right($0, $1), resource($0), operation($1);
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn authorizer_authority_checks(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "authorizer authority checks".to_string();
    let filename = "test011_authorizer_authority_caveats".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                operation("read");
                check if right($0, $1), resource($0), operation($1);
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn authority_checks(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "authority checks".to_string();
    let filename = "test012_authority_caveats".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if resource("file1")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "file1".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file1");
                operation("read");
                allow if true
            "#,
        ),
    );

    validations.insert(
        "file2".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                operation("read");
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn block_rules(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "block rules".to_string();
    let filename = "test013_block_rules".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block!(r#"
        // generate valid_date("file1") if before Thursday, December 31, 2030 12:59:59 PM UTC
        valid_date("file1") <- time($0), resource("file1"), $0 <= 2030-12-31T12:59:59Z;

        // generate a valid date fact for any file other than "file1" if before Friday, December 31, 1999 12:59:59 PM UTC
        valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59Z, !["file1"].contains($1);

        check if valid_date($0), resource($0);
    "#)).unwrap();

    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "file1".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file1");
                time(2020-12-21T09:23:12Z);
                allow if true
            "#,
        ),
    );

    validations.insert(
        "file2".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                time(2020-12-21T09:23:12Z);
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn regex_constraint(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "regex_constraint".to_string();
    let filename = "test014_regex_constraint".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if resource($0), $0.matches("file[0-9]+.txt")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "file1".to_string(),
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
    );

    validations.insert(
        "file123".to_string(),
        validate_token(root, &data[..], r#"resource("file123.txt"); allow if true"#),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn multi_queries_checks(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "multi queries checks".to_string();
    let filename = "test015_multi_queries_caveats".to_string();
    let token;

    let biscuit1 = biscuit!(r#"must_be_present("hello")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"check if must_be_present($0) or must_be_present($0); allow if true"#,
        ),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn check_head_name(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "check head name should be independent from fact names".to_string();
    let filename = "test016_caveat_head_name".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if resource("hello")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!(r#"query("test")"#))
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn expressions(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test expression syntax and all available operations".to_string();
    let filename = "test017_expressions".to_string();
    let token;

    let biscuit = biscuit!(r#"
        //boolean true
        check if true;
        //boolean false and negation
        check if !false;
        //boolean and
        check if !false && true;
        //boolean or
        check if false || true;
        //boolean parens
        check if (true || false) && true;
        // boolean equality
        check if true == true;
        check if false == false;

        //integer less than
        check if 1 < 2;
        //integer greater than
        check if 2 > 1;
        //integer less or equal
        check if 1 <= 2;
        check if 1 <= 1;
        //integer greater or equal
        check if 2 >= 1;
        check if 2 >= 2;
        //integer equal
        check if 3 == 3;
        //integer add sub mul div
        check if 1 + 2 * 3 - 4 /2 == 5;

        // string prefix and suffix
        check if "hello world".starts_with("hello") && "hello world".ends_with("world");
        // string regex
        check if "aaabde".matches("a*c?.e");
        // string contains
        check if "aaabde".contains("abd");
        // string concatenation
        check if "aaabde" == "aaa" + "b" + "de";
        // string equal
        check if "abcD12" == "abcD12";

        //date less than
        check if 2019-12-04T09:46:41+00:00 < 2020-12-04T09:46:41+00:00;
        //date greater than
        check if 2020-12-04T09:46:41+00:00 > 2019-12-04T09:46:41+00:00;
        //date less or equal
        check if 2019-12-04T09:46:41+00:00 <= 2020-12-04T09:46:41+00:00;
        check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00;
        //date greater or equal
        check if 2020-12-04T09:46:41+00:00 >= 2019-12-04T09:46:41+00:00;
        check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00;
        //date equal
        check if 2020-12-04T09:46:41+00:00 == 2020-12-04T09:46:41+00:00;

        //bytes equal
        check if hex:12ab == hex:12ab;

        // set contains
        check if [1, 2].contains(2);
        check if [2020-12-04T09:46:41+00:00, 2019-12-04T09:46:41+00:00].contains(2020-12-04T09:46:41+00:00);
        check if [true, false, true].contains(true);
        check if ["abc", "def"].contains("abc");
        check if [hex:12ab, hex:34de].contains(hex:34de);
        check if [1, 2].contains([2]);
        // set equal
        check if [1, 2] == [1, 2];
        // set intersection
        check if [1, 2].intersection([2, 3]) == [2];
        // set union
        check if [1, 2].union([2, 3]) == [1, 2, 3];
        // chained method calls
        check if [1, 2, 3].intersection([1, 2]).contains(1);
        // chained method calls with unary method
        check if [1, 2, 3].intersection([1, 2]).length() == 2;
    "#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn unbound_variables_in_rule(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "invalid block rule with unbound_variables".to_string();
    let filename = "test018_unbound_variables_in_rule".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if operation("read")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();

    let mut block2 = BlockBuilder::new();

    // this one does not go through the parser because it checks for unused variables
    block2
        .add_rule(rule(
            "operation",
            &[var("unbound"), string("read")],
            &[pred("operation", &[var("any1"), var("any2")])],
        ))
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"operation("write"); allow if true"#),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn generating_ambient_from_variables(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "invalid block rule generating an #authority or #ambient symbol with a variable"
        .to_string();
    let filename = "test019_generating_ambient_from_variables".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if operation("read")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!(r#"operation("read") <- operation($any)"#))
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"operation("write"); allow if true"#),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn sealed_token(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "sealed token".to_string();
    let filename = "test020_sealed".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, &filename);
        let t = Biscuit::from(&v[..], root.public()).unwrap();

        let actual = biscuit2.print();
        let expected = t.print();
        print_diff(&actual, &expected);
        v
    } else {
        let data = biscuit2.seal().unwrap().to_vec().unwrap();
        write_testcase(target, &filename, &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"resource("file1"); operation("read"); allow if true"#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn parsing(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "parsing".to_string();
    let filename = "test021_parsing".to_string();
    let token;

    let biscuit1 = biscuit!("ns::fact_123(\"hello é\t😁\")")
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            "check if ns::fact_123(\"hello é\t😁\"); allow if true",
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn default_symbols(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "default_symbols".to_string();
    let filename = "test022_default_symbols".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"read(0);write(1);resource(2);operation(3);right(4);time(5);
    role(6);owner(7);tenant(8);namespace(9);user(10);team(11);
    service(12);admin(13);email(14);group(15);member(16);
    ip_address(17);client(18);client_ip(19);domain(20);path(21);
    version(22);cluster(23);node(24);hostname(25);nonce(26);query(27)"#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
            check if read(0),write(1),resource(2),operation(3),right(4),
                time(5),role(6),owner(7),tenant(8),namespace(9),user(10),team(11),
                service(12),admin(13),email(14),group(15),member(16),ip_address(17),
                client(18),client_ip(19),domain(20),path(21),version(22),cluster(23),
                node(24),hostname(25),nonce(26),query(27);
            allow if true
        "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn execution_scope(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "execution scope".to_string();
    let filename = "test023_execution_scope".to_string();
    let token;

    let biscuit1 = biscuit!("authority_fact(1)")
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!("block1_fact(1)"))
        .unwrap();

    let keypair3 = KeyPair::new_with_rng(&mut rng);
    let biscuit3 = biscuit2
        .append_with_keypair(
            &keypair3,
            block!(
                r#"
                check if authority_fact($var);
                check if block1_fact($var);
            "#
            ),
        )
        .unwrap();
    token = print_blocks(&biscuit3);

    let data = write_or_load_testcase(target, &filename, root, &biscuit3, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn third_party(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "third party".to_string();
    let filename = "test024_third_party".to_string();
    let token;

    let external = KeyPair::new_with_rng(&mut rng);
    let biscuit1 = biscuit!(
        r#"
        right("read");
        check if group("admin") trusting {external_pub}
    "#,
        external_pub = external.public()
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let req = biscuit1.third_party_request().unwrap();

    let res = req
        .create_block(
            &external.private(),
            block!(
                r#"
                group("admin");
                check if right("read");
            "#
            ),
        )
        .unwrap();
    let keypair2 = KeyPair::new_with_rng(&mut rng);
    let biscuit2 = biscuit1
        .append_third_party_with_keypair(external.public(), res, keypair2)
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn check_all(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "block rules".to_string();
    let filename = "test025_check_all".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        allowed_operations(["A", "B"]);
        check all operation($op), allowed_operations($allowed), $allowed.contains($op);
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "A, B".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                operation("A");
                operation("B");
                allow if true
            "#,
        ),
    );

    validations.insert(
        "A, invalid".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                operation("A");
                operation("invalid");
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn public_keys_interning(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "public keys interning".to_string();
    let filename = "test026_public_keys_interning".to_string();
    let token;

    let external1 = KeyPair::new_with_rng(&mut rng);
    let external2 = KeyPair::new_with_rng(&mut rng);
    let external3 = KeyPair::new_with_rng(&mut rng);

    let biscuit1 = biscuit!(
        r#"
        query(0);
        check if true trusting previous, {k1};
    "#,
        k1 = external1.public()
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let req1 = biscuit1.third_party_request().unwrap();

    let res1 = req1
        .create_block(
            &external1.private(),
            block!(
                r#"
        query(1);
        query(1,2) <- query(1), query(2) trusting {k2};
        check if query(2), query(3) trusting {k2};
        check if query(1) trusting {k1};
        "#,
                k1 = external1.public(),
                k2 = external2.public(),
            ),
        )
        .unwrap();

    let biscuit2 = biscuit1
        .append_third_party_with_keypair(external1.public(), res1, KeyPair::new_with_rng(&mut rng))
        .unwrap();

    let req2 = biscuit2.third_party_request().unwrap();
    let res2 = req2
        .create_block(
            &external2.private(),
            block!(
                r#"
        query(2);
        check if query(2), query(3) trusting {k2};
        check if query(1) trusting {k1};
        "#,
                k1 = external1.public(),
                k2 = external2.public(),
            ),
        )
        .unwrap();

    let biscuit3 = biscuit2
        .append_third_party_with_keypair(external2.public(), res2, KeyPair::new_with_rng(&mut rng))
        .unwrap();

    let req3 = biscuit3.third_party_request().unwrap();
    let res3 = req3
        .create_block(
            &external2.private(),
            block!(
                r#"
        query(3);
        check if query(2), query(3) trusting {k2};
        check if query(1) trusting {k1};
        "#,
                k1 = external1.public(),
                k2 = external2.public(),
            ),
        )
        .unwrap();

    let biscuit4 = biscuit3
        .append_third_party_with_keypair(external2.public(), res3, KeyPair::new_with_rng(&mut rng))
        .unwrap();

    let biscuit5 = biscuit4
        .append_with_keypair(
            &KeyPair::new_with_rng(&mut rng),
            block!(
                r#"
            query(4);
            check if query(2) trusting {k2};
            check if query(4) trusting {k3};
            "#,
                k2 = external2.public(),
                k3 = external3.public(),
            ),
        )
        .unwrap();

    token = print_blocks(&biscuit5);

    let data = write_or_load_testcase(target, &filename, root, &biscuit5, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            &format!(
                r#"
              check if query(1,2) trusting ed25519/{k1}, ed25519/{k2};
              deny if query(3);
              deny if query(1,2);
              deny if query(0) trusting ed25519/{k1};
              allow if true;
            "#,
                k1 = &external1.public().to_bytes_hex(),
                k2 = &external2.public().to_bytes_hex(),
            ),
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn integer_wraparound(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "integer wraparound".to_string();
    let filename = "test027_integer_wraparound".to_string();
    let token;

    let biscuit = biscuit!(
        r#"
          // integer overflows must abort evaluating the whole expression
          // todo update this test when integer overflows abort
          // the whole datalog evaluation
          check if true || 10000000000 * 10000000000 != 0;
          check if true || 9223372036854775807 + 1 != 0;
          check if true || -9223372036854775808 - 1 != 0;
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], &format!(r#"allow if true;"#)),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn expressions_v4(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test expression syntax and all available operations (v4 blocks)".to_string();
    let filename = "test028_expressions_v4".to_string();
    let token;

    let biscuit = biscuit!(
        r#"
        //integer not equal
        check if 1 != 3;
        //integer bitwise and or xor
        check if 1 | 2 ^ 3 == 0;
        // string not equal
        check if "abcD12x" != "abcD12";
        //date not equal
        check if 2022-12-04T09:46:41+00:00 != 2020-12-04T09:46:41+00:00;
        //bytes not equal
        check if hex:12abcd != hex:12ab;
        // set not equal
        check if [1, 4] != [1, 2];
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();
    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
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
            public_keys: token
                .block_public_keys(i)
                .unwrap()
                .into_inner()
                .iter()
                .map(|k| k.print())
                .collect(),
            external_key: token.block_external_key(i).unwrap().map(|k| k.print()),
        });
    }

    v
}
