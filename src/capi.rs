use rand::prelude::*;
use std::{
    fmt,
    ffi::{CStr, CString},
    os::raw::c_char,
    cell::RefCell,
};

enum Error {
    Biscuit(crate::error::Token),
    InvalidArgument,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidArgument => write!(f, "invalid argument"),
            Error::Biscuit(e) => write!(f, "{}", e),
        }
    }
}


thread_local! {
    static LAST_ERROR: RefCell<Option<Error>> = RefCell::new(None);
}

fn update_last_error(err: Error) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(err);
    });
}

#[no_mangle]
pub extern fn error_message() -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST_ERROR.with(|prev| {
        match *prev.borrow() {
            Some(ref err) => {
                let err = CString::new(err.to_string()).ok();
                LAST.with(|ret| {
                    *ret.borrow_mut() = err;
                    ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
                })
            },
            None => std::ptr::null(),
        }
    })
}

pub struct Biscuit(crate::token::Biscuit);
pub struct KeyPair(crate::crypto::KeyPair);
pub struct PublicKey(crate::crypto::PublicKey);
pub struct BiscuitBuilder<'a>(crate::token::builder::BiscuitBuilder<'a>);
pub struct BlockBuilder(crate::token::builder::BlockBuilder);
pub struct Verifier<'a>(crate::token::verifier::Verifier<'a>);

#[repr(C)]
pub struct Slice {
    ptr: *const u8,
    len: usize,
}

#[repr(C)]
pub struct Bytes {
    ptr: *mut u8,
    len: usize,
    capacity: usize,
}

impl Slice {
    fn to_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn keypair_new<'a>(
    seed: Slice,
) -> Option<Box<KeyPair>> {
    let slice = seed.to_slice();
    if slice.len() != 32 {
        update_last_error(Error::InvalidArgument);
        return None;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(slice);

    let mut rng: StdRng = SeedableRng::from_seed(seed);

    Some(Box::new(KeyPair(crate::crypto::KeyPair::new(&mut rng))))
}

#[no_mangle]
pub unsafe extern "C" fn keypair_public(
    kp: Option<&KeyPair>,
) -> Option<Box<PublicKey>> {
    if kp.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let  kp = kp?;

    Some(Box::new(PublicKey((*kp).0.public())))
}

#[no_mangle]
pub unsafe extern "C" fn keypair_free(
    _kp: Option<Box<KeyPair>>,
) {

}

#[no_mangle]
pub unsafe extern "C" fn public_key_free(
    _kp: Option<Box<PublicKey>>,
) {
}


#[no_mangle]
pub unsafe extern "C" fn biscuit_builder<'a>(
    keypair: Option<&'a KeyPair>,
) -> Option<Box<BiscuitBuilder<'a>>> {
    if keypair.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let keypair = keypair?;

    Some(Box::new(BiscuitBuilder(
        crate::token::Biscuit::builder(&keypair.0),
    )))
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_add_authority_fact<'a>(
    builder: Option<&mut BiscuitBuilder<'a>>,
    fact: *const c_char,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    let fact = CStr::from_ptr(fact);
    let s = fact.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    builder.0.add_authority_fact(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_add_authority_rule<'a>(
    builder: Option<&mut BiscuitBuilder<'a>>,
    rule: *const c_char,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    let rule = CStr::from_ptr(rule);
    let s = rule.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    builder.0.add_authority_rule(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_add_authority_caveat<'a>(
    builder: Option<&mut BiscuitBuilder<'a>>,
    caveat: *const c_char,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    let caveat = CStr::from_ptr(caveat);
    let s = caveat.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    builder.0.add_authority_caveat(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_build<'a>(
    builder: Option<Box<BiscuitBuilder<'a>>>,
    seed: Slice,
) -> Option<Box<Biscuit>> {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let builder = builder?;

    let slice = seed.to_slice();
    if slice.len() != 32 {
        return None;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(slice);

    println!("building token");
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    (*builder).0.build(&mut rng).map(Biscuit).map(Box::new).ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_free<'a>(
    _builder: Option<Box<BiscuitBuilder<'a>>>,
) {
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_from(
    biscuit: Slice,
) -> Option<Box<Biscuit>> {
    let biscuit = biscuit.to_slice();

    crate::token::Biscuit::from(biscuit).map(Biscuit).map(Box::new).ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_from_sealed(
    biscuit: Slice,
    secret: Slice,
) -> Option<Box<Biscuit>> {
    let biscuit = biscuit.to_slice();
    let secret = secret.to_slice();

    crate::token::Biscuit::from_sealed(biscuit, secret).map(Biscuit).map(Box::new).ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_serialize(
    biscuit: Option<&Biscuit>,
) -> Bytes {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return Bytes {
            ptr: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        };
    }

    let biscuit = biscuit.unwrap();

    (*biscuit).0.to_vec().map(|mut v| {
        let res = Bytes {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            capacity: v.capacity(),
        };

        std::mem::forget(v);
        res
    }).unwrap_or_else(|e| {
        update_last_error(Error::Biscuit(e));
        Bytes {
            ptr: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_serialize_sealed(
    biscuit: Option<&Biscuit>,
    secret: Slice,
) -> Bytes {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return Bytes {
            ptr: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        };
    }

    let biscuit = biscuit.unwrap();
    let secret = secret.to_slice();

    (*biscuit).0.seal(secret).map(|mut v| {
        let res = Bytes {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            capacity: v.capacity(),
        };

        std::mem::forget(v);
        res
    }).unwrap_or_else(|e| {
        update_last_error(Error::Biscuit(e));
        Bytes {
            ptr: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_create_block(
    biscuit: Option<&Biscuit>,
) -> Option<Box<BlockBuilder>> {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let biscuit = biscuit?;

    Some(Box::new(BlockBuilder((biscuit.0.create_block()))))
}


#[no_mangle]
pub unsafe extern "C" fn biscuit_verify<'a, 'b>(
    biscuit: Option<&'a Biscuit>,
    root: Option<&'b PublicKey>,
) -> Option<Box<Verifier<'a>>> {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let biscuit = biscuit?;
    if root.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let root = root?;

    (*biscuit).0.verify((*root).0).map(Verifier).map(Box::new).ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_free(
    _biscuit: Option<Box<Biscuit>>,
) {
}

#[no_mangle]
pub unsafe extern "C" fn block_builder_add_fact(
    builder: Option<&mut BlockBuilder>,
    fact: *const c_char,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    let fact = CStr::from_ptr(fact);
    let s = fact.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    builder.0.add_fact(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn block_builder_add_rule(
    builder: Option<&mut BlockBuilder>,
    rule: *const c_char,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    let rule = CStr::from_ptr(rule);
    let s = rule.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    builder.0.add_rule(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn block_builder_add_caveat(
    builder: Option<&mut BlockBuilder>,
    caveat: *const c_char,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    let caveat = CStr::from_ptr(caveat);
    let s = caveat.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    builder.0.add_caveat(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn block_builder_free(
    _builder: Option<Box<BlockBuilder>>,
) {
}

#[no_mangle]
pub unsafe extern "C" fn verifier_add_fact(
    verifier: Option<&mut Verifier>,
    fact: *const c_char,
) -> bool {
    if verifier.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let verifier = verifier.unwrap();

    let fact = CStr::from_ptr(fact);
    let s = fact.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    verifier.0.add_fact(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn verifier_add_rule(
    verifier: Option<&mut Verifier>,
    rule: *const c_char,
) -> bool {
    if verifier.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let verifier = verifier.unwrap();

    let rule = CStr::from_ptr(rule);
    let s = rule.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    verifier.0.add_rule(s.unwrap()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn verifier_add_caveat(
    verifier: Option<&mut Verifier>,
    caveat: *const c_char,
) -> bool {
    if verifier.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let verifier = verifier.unwrap();

    let caveat = CStr::from_ptr(caveat);
    let s = caveat.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    verifier.0.add_caveat(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn verifier_verify(
    verifier: Option<&mut Verifier>,
) -> bool {
    if verifier.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let verifier = verifier.unwrap();

    match verifier.0.verify() {
        Ok(()) => true,
        Err(e) => {
            update_last_error(Error::Biscuit(e));
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn verifier_print(
    verifier: Option<&mut Verifier>,
) -> *mut c_char {
    if verifier.is_none() {
        update_last_error(Error::InvalidArgument);
        return std::ptr::null_mut();
    }
    let verifier = verifier.unwrap();

    match CString::new(verifier.0.print_world()) {
        Ok(s) => s.into_raw(),
        Err(_) => {
            update_last_error(Error::InvalidArgument);
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn verifier_free<'a>(
    _verifier: Option<Box<Verifier<'a>>>,
) {
}

#[no_mangle]
pub unsafe extern "C" fn bytes_free(
    bytes: Bytes,
) {
    if bytes.ptr != std::ptr::null_mut() {
        let _v = Vec::from_raw_parts(bytes.ptr, bytes.len, bytes.capacity);
    }
}

#[no_mangle]
pub unsafe extern "C" fn string_free(
  ptr: *mut c_char,
) {
    if ptr != std::ptr::null_mut() {
        CString::from_raw(ptr);
    }
}

