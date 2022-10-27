use biscuit_quote::{authorizer, authorizer_merge, biscuit, biscuit_merge, block, block_merge};

#[test]
fn block_macro() {
    let mut b = block!(
        r#"fact("test", hex:aabbcc, [true], {my_key});
            rule($0, true) <- fact($0, $1, $2, {my_key});
            check if {my_key}.starts_with("my");
            "#,
        my_key = "my_value",
    );

    block_merge!(&mut b, r#"appended(true);"#);

    assert_eq!(
        b.to_string(),
        r#"fact("test", hex:aabbcc, [ true], "my_value");
appended(true);
rule($0, true) <- fact($0, $1, $2, "my_value");
check if "my_value".starts_with("my");
"#,
    );
}

#[test]
fn block_macro_trailing_comma() {
    let b = block!(r#"fact({my_key});"#, my_key = "test",);
    assert_eq!(
        b.to_string(),
        r#"fact("test");
"#,
    );
}

#[test]
fn authorizer_macro() {
    let external_key = "test";
    let mut b = authorizer!(
        r#"fact({external_key}, hex:aabbcc, [ true], {my_key});
        rule($0, true) <- fact($0, $1, $2, {my_key});
        check if {my_key}.starts_with("my");
        allow if {other_key};
        "#,
        my_key = "my_value",
        other_key = false,
    );

    authorizer_merge!(
        &mut b,
        r#"appended(true);
        allow if true;
      "#
    );

    assert_eq!(
        b.dump_code(),
        r#"fact("test", hex:aabbcc, [ true], "my_value");
appended(true);
rule($0, true) <- fact($0, $1, $2, "my_value");
check if "my_value".starts_with("my");
allow if false;
allow if true;
"#,
    );
}

#[test]
fn authorizer_macro_trailing_comma() {
    let b = authorizer!(r#"fact("test", {my_key});"#, my_key = "my_value",);
    assert_eq!(
        b.dump_code(),
        r#"fact("test", "my_value");
"#,
    );
}

#[test]
fn biscuit_macro() {
    use biscuit_auth::PublicKey;
    let pubkey = PublicKey::from_bytes(
        &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db").unwrap(),
    )
    .unwrap();

    let s = String::from("my_value");
    let mut b = biscuit!(
        r#"fact("test", hex:aabbcc, [ true], {my_key}, {my_key_bytes});
        rule($0, true) <- fact($0, $1, $2, {my_key}, {my_key_bytes});
        check if {my_key}.starts_with("my") trusting {pubkey};
        check if true trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
        "#,
        my_key = "my_value",
        my_key_bytes = s.into_bytes(),
        pubkey = pubkey,
    );

    biscuit_merge!(
        &mut b,
        r#"appended(true);
        check if true;
      "#
    );

    assert_eq!(
        b.dump_code(),
        r#"fact("test", hex:aabbcc, [ true], "my_value", hex:6d795f76616c7565);
appended(true);
rule($0, true) <- fact($0, $1, $2, "my_value", hex:6d795f76616c7565);
check if "my_value".starts_with("my") trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
check if true trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
check if true;
"#,
    );
}

#[test]
fn biscuit_macro_trailing_comma() {
    let b = biscuit!(r#"fact("test", {my_key});"#, my_key = "my_value",);
    assert_eq!(
        b.dump_code(),
        r#"fact("test", "my_value");
"#,
    );
}
