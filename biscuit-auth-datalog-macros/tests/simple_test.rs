extern crate biscuit_quote;
use biscuit_quote::block;

#[test]
fn it_works() {
    let b = block!(
        r#"fact("test", hex:aabbcc, [true], {my_key});
            rule($0, true) <- fact($0, $1, $2, {my_key});
            check if {my_key}.starts_with("my");
            "#,
        my_key = "my_value",
        other_key = false,
    );
    assert_eq!(
        b.to_string(),
        r#"fact("test", hex:aabbcc, [ true], "my_value");
rule($0, true) <- fact($0, $1, $2, "my_value");
check if "my_value".starts_with("my");
"#,
    );
}

#[test]
fn it_works_trailing_comma() {
    let b = block!(r#"fact("test");"#, my_key = "my_value",);
    assert_eq!(
        b.to_string(),
        r#"fact("test");
"#,
    );
}
