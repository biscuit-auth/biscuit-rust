//! Biscuit authentication and authorization token
//!
//! Biscuit is an authorization token for microservices architectures with the following properties:
//!
//! * decentralized validation: any node could validate the token only with public information;
//! * offline delegation: a new, valid token can be created from another one by attenuating its rights, by its holder, without communicating with anyone;
//! * capabilities based: authorization in microservices should be tied to rights related to the request, instead of relying to an identity that might not make sense to the verifier;
//! * flexible rights managements: the token uses a logic language to specify attenuation and add bounds on ambient data;
//! * small enough to fit anywhere (cookies, etc).
//!
//! Non goals:
//!
//! * This is not a new authentication protocol. Biscuit tokens can be used as opaque tokens delivered by other systems such as OAuth.
//! * Revocation: while tokens come with expiration dates, revocation requires external state management.
//!
//! # Usage
//!
//! In this example we will see how we can create a token, add some caveats,
//! serialize and deserialize a token, append more caveats, and validate
//! those caveats in the context of a request:
//!
//! ```rust
//! extern crate rand;
//! extern crate biscuit;
//!
//! use biscuit::{crypto::KeyPair, token::{Biscuit, verifier::Verifier, builder::*}, error};
//!
//! fn main() -> Result<(), error::Token> {
//!   let mut rng = rand::thread_rng();
//!
//!   // let's generate the root key pair. The root public key will be necessary
//!   // to verify the token
//!   let root = KeyPair::new(&mut rng);
//!   let public_key = root.public();
//!
//!   // creating a first token
//!   let token1 = {
//!     // the first block of the token is the authority block. It contains global
//!     // information like which operation types are available
//!     let mut builder = Biscuit::builder(&mut rng, &root);
//!
//!     // let's define some access rights
//!     // every fact added to the authority block must have the authority fact
//!     builder.add_authority_fact(&fact("right", &[s("authority"), string("/a/file1.txt"), s("read")]));
//!     builder.add_authority_fact(&fact("right", &[s("authority"), string("/a/file1.txt"), s("write")]));
//!     builder.add_authority_fact(&fact("right", &[s("authority"), string("/a/file2.txt"), s("read")]));
//!     builder.add_authority_fact(&fact("right", &[s("authority"), string("/b/file3.txt"), s("write")]));
//!
//!     // we can now create the token
//!     let biscuit = builder.build()?;
//!     println!("biscuit (authority): {}", biscuit.print());
//!
//!     biscuit.to_vec()?
//!   };
//!
//!   // this token is only 266 bytes, holding the authority data and the signature
//!   assert_eq!(token1.len(), 266);
//!
//!   // now let's add some restrictions to this token
//!   // we want to limit access to `/a/file1.txt` and to read operations
//!   let token2 = {
//!     // the token is deserialized, the signature is verified
//!     let deser = Biscuit::from(&token1)?;
//!
//!     let mut builder = deser.create_block();
//!
//!     // caveats are implemented as logic rules. If the rule produces something,
//!     // the caveat is successful
//!     builder.add_caveat(&rule(
//!       // the rule's name
//!       "caveat",
//!       // the "head" of the rule, defining the kind of result that is produced
//!       &[s("resource")],
//!       // here we require the presence of a "resource" fact with the "ambient" tag
//!       // (meaning it is provided by the verifier)
//!       &[
//!         pred("resource", &[s("ambient"), string("/a/file1.txt")]),
//!         // we restrict to read operations
//!         pred("operation", &[s("ambient"), s("read")]),
//!       ],
//!     ));
//!
//!     let keypair = KeyPair::new(&mut rng);
//!     // we can now create a new token
//!     let biscuit = deser.append(&mut rng, &keypair, builder.build())?;
//!     println!("biscuit (authority): {}", biscuit.print());
//!
//!     biscuit.to_vec()?
//!   };
//!
//!   // this new token fits in 402 bytes
//!   assert_eq!(token2.len(), 402);
//!
//!   /************** VERIFICATION ****************/
//!
//!   // let's deserialize the token:
//!   let biscuit2 = Biscuit::from(&token2)?;
//!
//!   // let's define 3 verifiers (corresponding to 3 different requests):
//!   // - one for /a/file1.txt and a read operation
//!   // - one for /a/file1.txt and a write operation
//!   // - one for /a/file2.txt and a read operation
//!
//!   let mut v1 = biscuit2.verify(public_key)?;
//!   v1.add_resource("/a/file1.txt");
//!   v1.add_operation("read");
//!   // we will check that the token has the corresponding right
//!   v1.add_rule(rule("read_right",
//!     &[s("read_right")],
//!     &[pred("right", &[s("authority"), string("/a/file1.txt"), s("read")])]
//!   ));
//!
//!   let mut v2 = biscuit2.verify(public_key)?;
//!   v2.add_resource("/a/file1.txt");
//!   v2.add_operation("write");
//!   v2.add_rule(rule("write_right",
//!     &[s("write_right")],
//!     &[pred("right", &[s("authority"), string("/a/file1.txt"), s("write")])]
//!   ));
//!
//!   let mut v3 = biscuit2.verify(public_key)?;
//!   v3.add_resource("/a/file2.txt");
//!   v3.add_operation("read");
//!   v2.add_rule(rule("read_right",
//!     &[s("read_right")],
//!     &[pred("right", &[s("authority"), string("/a/file2.txt"), s("read")])]
//!   ));
//!
//!   // the token restricts to read operations:
//!   assert!(v1.verify().is_ok());
//!   // the second verifier requested a read operation
//!   assert!(v2.verify().is_err());
//!   // the third verifier requests /a/file2.txt
//!   assert!(v3.verify().is_err());
//!
//!   Ok(())
//! }
//! ```
//!
//! # Concepts
//!
//! ## blocks
//!
//! A Biscuit token is made with a list of blocks defining data and caveats that
//! must be validated upon reception with a request. Any failed caveat will invalidate
//! the entire token.
//!
//! If you hold a valid token, it is possible to add a new block to restrict further
//! the token, like limiting access to one particular resource, or adding a short
//! expiration date. This will generate a new, valid token. This can be done offline,
//! without asking the original token creator.
//!
//! On the other hand, if a block is modified or removed, the token will fail the
//! cryptographic signature verification.
//!
//! ## Cryptography
//!
//! Biscuit tokens get inspiration from macaroons and JSON Web Tokens, reproducing
//! useful features from both:
//!
//! - offline delegation like macaroons
//! - based on public key cryptography like JWT, so any application holding the root public key can verify a token (while macaroons are based on a root shared secret)
//!
//! ## A logic language for caveats: Datalog with constraints
//!
//! We rely on a modified version of Datalog, that can represent complex behaviours
//! in a compact form, and add flexible constraints on data.
//!
//! Here are examples of caveats that can be implemented with that language:
//!
//! - valid if the requested resource is "file.txt" and the operation is "read"
//! - valid if current time is before January 1st 2030, 00h00mn00s UTC
//! - source IP is in set [1.2.3.4, 5.6.7.8]
//! - resource matches prefix "/home/biscuit/data/"
//!
//! But it can also combine into more complex patterns, like: right is read if
//! user has read or user is member of organisation and organisation has read right
//! or other user with read right has delegated to user.
//!
//! Like Datalog, this language is based around facts and rules, but with some
//! slight modifications:
//!
//! - an authority fact starts with the `#authority` symbol. It can only be added in the authority block (or generated from rules in the authority rules). It provides the basic authorization data, like which rights exist
//! - an ambient fact starts with the `#ambient` symbol. It can only be provided by the verifier. It gives information on the current request, like which resource is accessed or the current time
//!
//! Blocks can provide facts but they cannot be authority or ambient facts. They
//! contain rules that use facts from the current block, or from the authority
//! and ambient contexts. If all rules in a block succeed, the block is validated.
//!
//! A caveat rule requires the presence of one or more facts, and can have additional
//! constraints on these facts (the constraints are implemented separately to simplify
//! the language implementation: among other things, it avoids implementing negation).
//! It is possible to create rules like these ones:
//!
//! - caveat = resource("file1")
//! - caveat = resource(0?) & owner("user1", 0?) // the 0? represents a "hole" that must be filled with the correct value
//! - caveat = time(0?) | 0? < 2019-02-05T23:00:00Z // expiration date
//! - application(0?) & operation(1?) &user(2?) & & right(app, 0?, 1?) & owner(2?, 0?) & credit(2?, 3?) | 3? > 0 // verifies that the user owns the applications, the application has the right on the operation, there's a credit information for the operation, and the credit is larger than 0
//!
//! ## Symbols and symbol tables
//!
//! To reduce the size of tokens, the language supports a data type called "symbol".
//! A symbol is a string that we can refer to with a number, an index in the symbol
//! table that is carried with the token. Symbols can be checked for equality, or
//! presence in a set, but lack the other constraints on strings like prefix or suffix
//! matching.
//!
//! They can be used for pretty printing of a fact or rule. As an example, with a table
//! containing `["resource", "operation", "read", "caveat1"], we could have the following rule:
//! `#4 <- #0("file.txt") & #1(#2)` that would be printed as `caveat1 <- resoucr("file.txt") & operation(read)`
//!
//! biscuit implementations come with a default symbol table to avoid transmitting
//! frequent values with every token.
extern crate bytes;
extern crate curve25519_dalek;
extern crate hmac;
extern crate prost;
extern crate prost_types;
extern crate rand_core;
extern crate sha2;

pub mod crypto;
pub mod datalog;
pub mod error;
pub mod format;
pub mod token;
