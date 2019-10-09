//! cryptographic operations
//!
//! Biscuit tokens are based on [aggregated gamma signatures](https://eprint.iacr.org/2018/414/20180510:203542).
//! This provides the fundamental operation for offline delegation: from a message
//! and a valid signature, it is possible to add a new message and produce a valid
//! signature for the whole.
//!
//! The implementation is based on [curve25519_dalek](https://github.com/dalek-cryptography/curve25519-dalek),
//! a Rust implementation of the Ristretto group over Ed25519.
#![allow(non_snake_case)]
use super::error;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand_core::{RngCore, CryptoRng};
use sha2::{Digest, Sha512};
use std::ops::Deref;
use wasm_bindgen::prelude::*;


#[wasm_bindgen]
pub struct KeyPair {
    pub(crate) private: Scalar,
    pub(crate) public: RistrettoPoint,
}

impl KeyPair {
    pub fn new<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let private = Scalar::random(rng);
        let public = private * RISTRETTO_BASEPOINT_POINT;

        KeyPair { private, public }
    }

    pub fn from(key: PrivateKey) -> Self {
        let private = key.0;

        let public = private * RISTRETTO_BASEPOINT_POINT;

        KeyPair { private, public }
    }

    #[allow(dead_code)]
    fn sign<T: RngCore + CryptoRng>(&self, rng: &mut T, message: &[u8]) -> (Scalar, Scalar) {
        let r = Scalar::random(rng);
        let A = r * RISTRETTO_BASEPOINT_POINT;
        let d = hash_points(&[A]);
        let e = hash_message(self.public, message);
        let z = r * d - e * self.private;
        (d, z)
    }

    pub fn private(&self) -> PrivateKey {
        PrivateKey(self.private)
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.public)
    }
}

#[allow(dead_code)]
fn verify(public: &RistrettoPoint, message: &[u8], signature: &(Scalar, Scalar)) -> bool {
    let (d, z) = signature;
    let e = hash_message(*public, message);
    let d_inv = d.invert();
    let A = z * d_inv * RISTRETTO_BASEPOINT_POINT + e * d_inv * public;

    hash_points(&[A]) == *d
}

#[wasm_bindgen]
pub struct PrivateKey(pub(crate) Scalar);

impl PrivateKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(&self, bytes: [u8; 32]) -> Option<Self> {
        Scalar::from_canonical_bytes(bytes).map(PrivateKey)
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub(crate) RistrettoPoint);

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    pub fn from_bytes(&self, bytes: &[u8]) -> Option<Self> {
        CompressedRistretto::from_slice(bytes)
            .decompress()
            .map(PublicKey)
    }
}

#[allow(dead_code)]
/// test structure for aggregated signatures
struct Token {
    pub messages: Vec<Vec<u8>>,
    pub keys: Vec<PublicKey>,
    pub signature: TokenSignature,
}

impl Token {
    #[allow(dead_code)]
    pub fn new<T: RngCore + CryptoRng>(rng: &mut T, keypair: &KeyPair, message: &[u8]) -> Self {
        let signature = TokenSignature::new(rng, keypair, message);

        Token {
            messages: vec![message.to_owned()],
            keys: vec![keypair.public()],
            signature,
        }
    }

    #[allow(dead_code)]
    pub fn append<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        keypair: &KeyPair,
        message: &[u8],
    ) -> Self {
        let signature = self.signature.sign(rng, keypair, message);

        let mut t = Token {
            messages: self.messages.clone(),
            keys: self.keys.clone(),
            signature,
        };

        t.messages.push(message.to_owned());
        t.keys.push(keypair.public());

        t
    }

    #[allow(dead_code)]
    pub fn verify(&self) -> Result<(), error::Signature> {
        self.signature.verify(&self.keys, &self.messages)
    }
}

#[derive(Clone, Debug)]
pub struct TokenSignature {
    pub parameters: Vec<RistrettoPoint>,
    pub z: Scalar,
}

impl TokenSignature {
    pub fn new<T: RngCore + CryptoRng>(rng: &mut T, keypair: &KeyPair, message: &[u8]) -> Self {
        let r = Scalar::random(rng);
        let A = r * RISTRETTO_BASEPOINT_POINT;
        let d = hash_points(&[A]);
        let e = hash_message(keypair.public, message);
        let z = r * d - e * keypair.private;

        TokenSignature {
            parameters: vec![A],
            z,
        }
    }

    pub fn sign<T: RngCore + CryptoRng>(&self, rng: &mut T, keypair: &KeyPair, message: &[u8]) -> Self {
        let r = Scalar::random(rng);
        let A = r * RISTRETTO_BASEPOINT_POINT;
        let d = hash_points(&[A]);
        let e = hash_message(keypair.public, message);
        let z = r * d - e * keypair.private;

        let mut t = TokenSignature {
            parameters: self.parameters.clone(),
            z: self.z + z,
        };

        t.parameters.push(A);
        t
    }

    pub fn verify<M: Deref<Target = [u8]>>(
        &self,
        public_keys: &[PublicKey],
        messages: &[M],
    ) -> Result<(), error::Signature> {
        if !(public_keys.len() == messages.len() && public_keys.len() == self.parameters.len()) {
            println!("invalid data");
            return Err(error::Signature::InvalidFormat);
        }

        let zP = self.z * RISTRETTO_BASEPOINT_POINT;
        let eiXi = public_keys
            .iter()
            .zip(messages)
            .map(|(pubkey, message)| {
                let e = hash_message((*pubkey).0, message);
                e * pubkey.0
            })
            .fold(RistrettoPoint::identity(), |acc, point| acc + point);

        let diAi = self
            .parameters
            .iter()
            .map(|A| {
                let d = hash_points(&[*A]);
                d * A
            })
            .fold(RistrettoPoint::identity(), |acc, point| acc + point);

        let res = zP + eiXi - diAi;

        /*
        println!("verify identity={:?}", RistrettoPoint::identity());
        println!("verify res={:?}", res);
        println!("verify identity={:?}", RistrettoPoint::identity().compress());
        println!("verify res={:?}", res.compress());
        println!("returning: {:?}", RistrettoPoint::identity() == res);
        */

        if RistrettoPoint::identity() == res {
            Ok(())
        } else {
            Err(error::Signature::InvalidSignature)
        }
    }
}

//FIXME: is the output value in the right set?
fn hash_points(points: &[RistrettoPoint]) -> Scalar {
    let mut h = Sha512::new();
    for point in points.iter() {
        h.input(point.compress().as_bytes());
    }

    Scalar::from_hash(h)
}

fn hash_message(point: RistrettoPoint, data: &[u8]) -> Scalar {
    let h = Sha512::new().chain(point.compress().as_bytes()).chain(data);

    Scalar::from_hash(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;
    use rand::prelude::*;

    #[test]
    fn basic_signature() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);

        let message = b"hello world";
        let keypair = KeyPair::new(&mut rng);

        let signature = keypair.sign(&mut rng, message);

        assert!(verify(&keypair.public, message, &signature));

        assert!(!verify(&keypair.public, b"AAAA", &signature));
    }

    #[test]
    fn three_messages() {
        //let mut rng: OsRng = OsRng::new().unwrap();
        //keep the same values in tests
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);

        let message1 = b"hello";
        let keypair1 = KeyPair::new(&mut rng);

        let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

        assert_eq!(token1.verify(), Ok(()), "cannot verify first token");

        println!("will derive a second token");

        let message2 = b"world";
        let keypair2 = KeyPair::new(&mut rng);

        let token2 = token1.append(&mut rng, &keypair2, &message2[..]);

        assert_eq!(token2.verify(), Ok(()), "cannot verify second token");

        println!("will derive a third token");

        let message3 = b"!!!";
        let keypair3 = KeyPair::new(&mut rng);

        let token3 = token2.append(&mut rng, &keypair3, &message3[..]);

        assert_eq!(token3.verify(), Ok(()), "cannot verify third token");
    }

    #[test]
    fn change_message() {
        //let mut rng: OsRng = OsRng::new().unwrap();
        //keep the same values in tests
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);

        let message1 = b"hello";
        let keypair1 = KeyPair::new(&mut rng);

        let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

        assert_eq!(token1.verify(), Ok(()), "cannot verify first token");

        println!("will derive a second token");

        let message2 = b"world";
        let keypair2 = KeyPair::new(&mut rng);

        let mut token2 = token1.append(&mut rng, &keypair2, &message2[..]);

        token2.messages[1] = Vec::from(&b"you"[..]);

        assert_eq!(
            token2.verify(),
            Err(error::Signature::InvalidSignature),
            "second token should not be valid"
        );

        println!("will derive a third token");

        let message3 = b"!!!";
        let keypair3 = KeyPair::new(&mut rng);

        let token3 = token2.append(&mut rng, &keypair3, &message3[..]);

        assert_eq!(
            token3.verify(),
            Err(error::Signature::InvalidSignature),
            "cannot verify third token"
        );
    }
}
