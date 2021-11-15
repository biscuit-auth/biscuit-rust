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
    /*let token = biscuit_auth::token::Biscuit::from(&data[..]).unwrap();

    println!("Token content:\n{}", token.print());*/
}
