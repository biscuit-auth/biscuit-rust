use biscuit_auth::{format::schema::ThirdPartyBlockRequest, Biscuit, KeyPair};
use rand::{prelude::StdRng, SeedableRng};

fn main() {
    let mut rng: StdRng = SeedableRng::seed_from_u64(0);
    let root = KeyPair::new_with_rng(&mut rng);
    let external = KeyPair::new_with_rng(&mut rng);

    let mut builder = Biscuit::builder(&root);

    let external_pub = hex::encode(external.public().to_bytes());

    builder
        .add_authority_check(
            format!("check if external_fact(\"hello\") trusting ed25519/{external_pub}").as_str(),
        )
        .unwrap();

    let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

    println!("biscuit1: {}", biscuit1.print());

    let serialized_req = biscuit1.third_party_request().unwrap();

    let req = biscuit_auth::Request::deserialize(&serialized_req).unwrap();
    let mut block = req.create_block();
    block.add_fact("external_fact(\"hello\")").unwrap();
    let res = req.create_response(external.private(), block).unwrap();

    let biscuit2 = biscuit1
        .append_third_party(external.public(), &res[..])
        .unwrap();

    println!("biscuit2: {}", biscuit2.print());

    let mut authorizer = biscuit1.authorizer().unwrap();
    authorizer.allow().unwrap();
    println!("authorize biscuit1:\n{:?}", authorizer.authorize());
    println!("world:\n{}", authorizer.print_world());

    let mut authorizer = biscuit2.authorizer().unwrap();
    authorizer.allow().unwrap();
    println!("authorize biscuit2:\n{:?}", authorizer.authorize());
    println!("world:\n{}", authorizer.print_world());
}
