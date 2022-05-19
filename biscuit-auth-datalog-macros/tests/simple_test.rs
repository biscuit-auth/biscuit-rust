extern crate biscuit_auth;
extern crate biscuit_quote;
use biscuit_auth::{Biscuit, KeyPair};
use biscuit_quote::block;

#[test]
fn it_works() {
    let root = KeyPair::new();
    let mut biscuit_builder = Biscuit::builder(&root);

    biscuit_builder
        .add_authority_fact("right(\"/a/file1.txt\", \"read\")")
        .unwrap();
    let biscuit = biscuit_builder.build().unwrap();

    let new = biscuit
        .append(block!(
            r#"fact("test", hex:aabbcc, [true], {my_key});
            rule($0, true) <- fact($0, $1, $2, {my_key});
            check if {my_key}.starts_with("my");
            "#,
            my_key = "my_value"
        ))
        .unwrap();
    println!("biscuit: {}", new.print());
    panic!("no");
}

/*
#[test]
fn it_works_with_2_parameters() {
    let toto = block!(r#"fact("test");"#, my_key = "my_value", my_key2 = 42);
    dbg!(toto);
    panic!("no");
}

#[test]
fn it_works_trailing_comma() {
    let toto = block!(r#"fact("test");"#, my_key = "my_value",);
    dbg!(toto);
    panic!("no");
}
*/
