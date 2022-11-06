#![cfg(feature = "serde-error")]
#![allow(unused_must_use)]
extern crate biscuit_auth as biscuit;

use biscuit::builder::BlockBuilder;
use biscuit::datalog::SymbolTable;
use biscuit::error;
use biscuit::macros::*;
use biscuit::Authorizer;
use biscuit::KeyPair;
use biscuit::{builder::*, builder_ext::*, Biscuit};
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

    results.push(scoped_rules(&mut rng, &target, &root, test));

    results.push(scoped_checks(&mut rng, &target, &root, test));

    results.push(expired_token(&mut rng, &target, &root, test));

    results.push(authorizer_scope(&mut rng, &target, &root, test));

    results.push(authorizer_authority_checks(&mut rng, &target, &root, test));

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

    results.push(parsing(&mut rng, &target, &root, test));

    results.push(default_symbols(&mut rng, &target, &root, test));

    results.push(execution_scope(&mut rng, &target, &root, test));

    results.push(third_party(&mut rng, &target, &root, test));

    results.push(check_all(&mut rng, &target, &root, test));

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
            println!("{}", result);
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
    pub facts: BTreeSet<String>,
    pub rules: BTreeSet<String>,
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
    let (mut facts, mut rules, mut checks, mut policies) = authorizer.dump();

    Validation {
        world: Some(AuthorizerWorld {
            facts: facts.drain(..).map(|f| f.to_string()).collect(),
            rules: rules.drain(..).map(|r| r.to_string()).collect(),
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

fn basic_token<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "basic token".to_string();
    let filename = "test1_basic.bc".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
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

    let data = if test {
        let v = load_testcase(target, "test1_basic");
        let t = Biscuit::from(&v[..], root.public()).unwrap();

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

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root2, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
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

fn invalid_signature_format<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "invalid signature format".to_string();
    let filename = "test3_invalid_signature_format.bc".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test3_invalid_signature_format");
        v
    } else {
        let serialized = biscuit2.container();
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
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
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

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test4_random_block");
        v
    } else {
        let serialized = biscuit2.container();
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
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
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

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test5_invalid_signature");
        v
    } else {
        let serialized = biscuit2.container();
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
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
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

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    let keypair3 = KeyPair::new_with_rng(rng);
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
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
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

    let biscuit1 = biscuit!(
        r#"
        user_id("alice");
        owner("alice", "file1");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
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

    let keypair3 = KeyPair::new_with_rng(rng);
    let biscuit3 = biscuit2.append_with_keypair(&keypair3, block3).unwrap();
    token = print_blocks(&biscuit3);

    let data = if test {
        let v = load_testcase(target, "test7_scoped_rules");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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

fn scoped_checks<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "scoped checks".to_string();
    let filename = "test8_scoped_checks.bc".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    let keypair3 = KeyPair::new_with_rng(rng);
    let biscuit3 = biscuit2
        .append_with_keypair(&keypair3, block!(r#"right("file2", "read")"#))
        .unwrap();
    token = print_blocks(&biscuit3);

    let data = if test {
        let v = load_testcase(target, "test8_scoped_checks");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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

fn expired_token<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "expired token".to_string();
    let filename = "test9_expired_token.bc".to_string();
    let token;

    let builder = Biscuit::builder();
    let biscuit1 = builder
        .build_with_rng(&root, SymbolTable::default(), rng)
        .unwrap();

    let mut block2 = block!(r#"check if resource("file1");"#);

    // January 1 2019
    block2.check_expiration_date(
        UNIX_EPOCH
            .checked_add(Duration::from_secs(49 * 365 * 24 * 3600))
            .unwrap(),
    );

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test9_expired_token");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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

fn authorizer_scope<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "authorizer scope".to_string();
    let filename = "test10_authorizer_scope.bc".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!(r#"right("file2", "read")"#))
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test10_authorizer_scope");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test10_authorizer_scope", &data[..]);

        data
    };

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
fn authorizer_authority_checks<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "authorizer authority checks".to_string();
    let filename = "test11_authorizer_authority_caveats.bc".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();
    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test11_authorizer_authority_caveats");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test11_authorizer_authority_caveats", &data[..]);
        data
    };

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

fn authority_checks<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "authority checks".to_string();
    let filename = "test12_authority_caveats.bc".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if resource("file1")"#)
        .build_with_rng(&root, SymbolTable::default(), rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test12_authority_caveats");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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

fn block_rules<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "block rules".to_string();
    let filename = "test13_block_rules.bc".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block!(r#"
        // generate valid_date("file1") if before Thursday, December 31, 2030 12:59:59 PM UTC
        valid_date("file1") <- time($0), resource("file1"), $0 <= 2030-12-31T12:59:59Z;

        // generate a valid date fact for any file other than "file1" if before Friday, December 31, 1999 12:59:59 PM UTC
        valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59Z, !["file1"].contains($1);

        check if valid_date($0), resource($0);
    "#)).unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test13_block_rules");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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

fn regex_constraint<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "regex_constraint".to_string();
    let filename = "test14_regex_constraint.bc".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if resource($0), $0.matches("file[0-9]+.txt")"#)
        .build_with_rng(&root, SymbolTable::default(), rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test14_regex_constraint");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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

fn multi_queries_checks<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "multi queries checks".to_string();
    let filename = "test15_multi_queries_caveats.bc".to_string();
    let token;

    let biscuit1 = biscuit!(r#"must_be_present("hello")"#)
        .build_with_rng(&root, SymbolTable::default(), rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test15_multi_queries_caveats");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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

fn check_head_name<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "check head name should be independent from fact names".to_string();
    let filename = "test16_caveat_head_name.bc".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if resource("hello")"#)
        .build_with_rng(&root, SymbolTable::default(), rng)
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!(r#"query("test")"#))
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test16_caveat_head_name");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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
        validate_token(root, &data[..], "allow if true"),
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

    let biscuit = biscuit!(r#"
        //boolean true
        check if true;
        //boolean false and negation
        check if !false;
        //boolean and
        check if !false && true;
        //boolean or
        check if false or true;
        //boolean parens
        check if (true || false) && true;

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
    "#)
        .build_with_rng(&root, SymbolTable::default(), rng)
        .unwrap();
    token = print_blocks(&biscuit);

    let data = if test {
        let v = load_testcase(target, "test17_expressions");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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
        validate_token(root, &data[..], "allow if true"),
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

    let biscuit1 = biscuit!(r#"check if operation("read")"#)
        .build_with_rng(&root, SymbolTable::default(), rng)
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

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test18_unbound_variables_in_rule");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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
        validate_token(root, &data[..], r#"operation("write"); allow if true"#),
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

    let biscuit1 = biscuit!(r#"check if operation("read")"#)
        .build_with_rng(&root, SymbolTable::default(), rng)
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!(r#"operation("read") <- operation($any)"#))
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test19_generating_ambient_from_variables");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
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
        validate_token(root, &data[..], r#"operation("write"); allow if true"#),
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

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test20_sealed");
        let t = Biscuit::from(&v[..], root.public()).unwrap();

        let actual = biscuit2.print();
        let expected = t.print();
        print_diff(&actual, &expected);
        v
    } else {
        let data = biscuit2.seal().unwrap().to_vec().unwrap();
        write_testcase(target, "test20_sealed", &data[..]);
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

fn parsing<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "parsing".to_string();
    let filename = "test21_parsing.bc".to_string();
    let token;

    let biscuit1 = biscuit!("ns::fact_123(\"hello é\t😁\")")
        .build_with_rng(&root, SymbolTable::default(), rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test21_parsing");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test21_parsing", &data[..]);
        data
    };

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

fn default_symbols<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "default_symbols".to_string();
    let filename = "test22_default_symbols.bc".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"read(0);write(1);resource(2);operation(3);right(4);time(5);
    role(6);owner(7);tenant(8);namespace(9);user(10);team(11);
    service(12);admin(13);email(14);group(15);member(16);
    ip_address(17);client(18);client_ip(19);domain(20);path(21);
    version(22);cluster(23);node(24);hostname(25);nonce(26);query(27)"#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();
    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test22_default_symbols");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test22_default_symbols", &data[..]);
        data
    };

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

fn execution_scope<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "execution scope".to_string();
    let filename = "test23_execution_scope.bc".to_string();
    let token;

    let biscuit1 = biscuit!("authority_fact(1)")
        .build_with_rng(&root, SymbolTable::default(), rng)
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!("block1_fact(1)"))
        .unwrap();

    let keypair3 = KeyPair::new_with_rng(rng);
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

    let data = if test {
        let v = load_testcase(target, "test23_execution_scope");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
        print_diff(&biscuit3.print(), &expected.print());
        v
    } else {
        let data = biscuit3.to_vec().unwrap();
        write_testcase(target, "test23_execution_scope", &data[..]);

        data
    };

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

fn third_party<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "third party".to_string();
    let filename = "test24_third_party.bc".to_string();
    let token;

    let external = KeyPair::new_with_rng(rng);
    let biscuit1 = biscuit!(
        r#"
        right("read");
        check if group("admin") trusting {external_pub}
    "#,
        external_pub = external.public()
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
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
    let keypair2 = KeyPair::new_with_rng(rng);
    let biscuit2 = biscuit1
        .append_third_party_with_keypair(external.public(), res, keypair2)
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, "test24_third_party");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
        print_diff(&biscuit2.print(), &expected.print());
        v
    } else {
        let data = biscuit2.to_vec().unwrap();
        write_testcase(target, "test24_third_party", &data[..]);

        data
    };

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

fn check_all<T: Rng + CryptoRng>(
    rng: &mut T,
    target: &str,
    root: &KeyPair,
    test: bool,
) -> TestResult {
    let title = "block rules".to_string();
    let filename = "test25_check_all.bc".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        allowed_operations(["A", "B"]);
        check all operation($op), allowed_operations($allowed), $allowed.contains($op);
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), rng)
    .unwrap();

    token = print_blocks(&biscuit1);

    let data = if test {
        let v = load_testcase(target, "test25_check_all");
        let expected = Biscuit::from(&v[..], root.public()).unwrap();
        print_diff(&biscuit1.print(), &expected.print());
        v
    } else {
        let data = biscuit1.to_vec().unwrap();
        write_testcase(target, "test25_check_all", &data[..]);

        data
    };

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
        "A, inalid".to_string(),
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
