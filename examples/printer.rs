fn main() {
    let mut args = std::env::args();
    args.next();
    let target = match args.next() {
        Some(arg) => arg,
        None => {
            println!("missing token path argument");
            return;
        }
    };

    let data = std::fs::read(target).unwrap();
    let token = biscuit_auth::UnverifiedBiscuit::from(&data[..]).unwrap();

    println!("Token content:");
    for i in 0..token.block_count() {
        println!("block {}:\n{}\n", i, token.print_block_source(i).unwrap());
    }
}
