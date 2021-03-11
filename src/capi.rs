use rand::prelude::*;
use std::{
    cell::RefCell,
    ffi::{CStr, CString},
    fmt,
    os::raw::c_char,
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
pub extern "C" fn error_message() -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(ref err) => {
            let err = CString::new(err.to_string()).ok();
            LAST.with(|ret| {
                *ret.borrow_mut() = err;
                ret.borrow()
                    .as_ref()
                    .map(|x| x.as_ptr())
                    .unwrap_or(std::ptr::null())
            })
        }
        None => std::ptr::null(),
    })
}

#[repr(C)]
pub enum ErrorKind {
    None,
    InvalidArgument,
    InternalError,
    FormatSignatureInvalidFormat,
    FormatSignatureInvalidSignature,
    FormatSealedSignature,
    FormatEmptyKeys,
    FormatUnknownPublickKey,
    FormatDeserializationError,
    FormatSerializationError,
    FormatBlockDeserializationError,
    FormatBlockSerializationError,
    FormatVersion,
    InvalidAuthorityIndex,
    InvalidBlockIndex,
    SymbolTableOverlap,
    MissingSymbols,
    Sealed,
    LogicInvalidAuthorityFact,
    LogicInvalidAmbientFact,
    LogicInvalidBlockFact,
    LogicInvalidBlockRule,
    LogicFailedChecks,
    LogicVerifierNotEmpty,
    LogicDeny,
    LogicNoMatchingPolicy,
    ParseError,
    TooManyFacts,
    TooManyIterations,
    Timeout,
    ConversionError,
}

#[no_mangle]
pub extern "C" fn error_kind() -> ErrorKind {
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(ref err) => match err {
            Error::InvalidArgument => ErrorKind::InvalidArgument,
            Error::Biscuit(e) => {
                use crate::error::*;
                match e {
                    Token::InternalError => ErrorKind::InternalError,
                    Token::Format(Format::Signature(Signature::InvalidFormat)) => {
                        ErrorKind::FormatSignatureInvalidFormat
                    }
                    Token::Format(Format::Signature(Signature::InvalidSignature)) => {
                        ErrorKind::FormatSignatureInvalidSignature
                    }
                    Token::Format(Format::SealedSignature) => ErrorKind::FormatSealedSignature,
                    Token::Format(Format::EmptyKeys) => ErrorKind::FormatEmptyKeys,
                    Token::Format(Format::UnknownPublicKey) => ErrorKind::FormatUnknownPublickKey,
                    Token::Format(Format::DeserializationError(_)) => {
                        ErrorKind::FormatDeserializationError
                    }
                    Token::Format(Format::SerializationError(_)) => {
                        ErrorKind::FormatSerializationError
                    }
                    Token::Format(Format::BlockDeserializationError(_)) => {
                        ErrorKind::FormatBlockDeserializationError
                    }
                    Token::Format(Format::BlockSerializationError(_)) => {
                        ErrorKind::FormatBlockSerializationError
                    }
                    Token::Format(Format::Version { .. }) => ErrorKind::FormatVersion,
                    Token::InvalidAuthorityIndex(_) => ErrorKind::InvalidAuthorityIndex,
                    Token::InvalidBlockIndex(_) => ErrorKind::InvalidBlockIndex,
                    Token::SymbolTableOverlap => ErrorKind::SymbolTableOverlap,
                    Token::MissingSymbols => ErrorKind::MissingSymbols,
                    Token::Sealed => ErrorKind::Sealed,
                    Token::ParseError => ErrorKind::ParseError,
                    Token::FailedLogic(Logic::InvalidAuthorityFact(_)) => {
                        ErrorKind::LogicInvalidAuthorityFact
                    }
                    Token::FailedLogic(Logic::InvalidAmbientFact(_)) => {
                        ErrorKind::LogicInvalidAmbientFact
                    }
                    Token::FailedLogic(Logic::InvalidBlockFact(_, _)) => {
                        ErrorKind::LogicInvalidBlockFact
                    }
                    Token::FailedLogic(Logic::InvalidBlockRule(_, _)) => {
                        ErrorKind::LogicInvalidBlockRule
                    }
                    Token::FailedLogic(Logic::FailedChecks(_)) => ErrorKind::LogicFailedChecks,
                    Token::FailedLogic(Logic::VerifierNotEmpty) => ErrorKind::LogicVerifierNotEmpty,
                    Token::FailedLogic(Logic::Deny(_)) => ErrorKind::LogicDeny,
                    Token::FailedLogic(Logic::NoMatchingPolicy) => ErrorKind::LogicNoMatchingPolicy,
                    Token::RunLimit(RunLimit::TooManyFacts) => ErrorKind::TooManyFacts,
                    Token::RunLimit(RunLimit::TooManyIterations) => ErrorKind::TooManyIterations,
                    Token::RunLimit(RunLimit::Timeout) => ErrorKind::Timeout,
                    Token::ConversionError(_) => ErrorKind::ConversionError,
                }
            }
        },
        None => ErrorKind::None,
    })
}

#[no_mangle]
pub extern "C" fn error_check_count() -> u64 {
    use crate::error::*;
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(Error::Biscuit(Token::FailedLogic(Logic::FailedChecks(ref v)))) => v.len() as u64,
        _ => 0,
    })
}

#[no_mangle]
pub extern "C" fn error_check_id(check_index: u64) -> u64 {
    use crate::error::*;
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(Error::Biscuit(Token::FailedLogic(Logic::FailedChecks(ref v)))) => {
            if check_index >= v.len() as u64 {
                u64::MAX
            } else {
                match v[check_index as usize] {
                    FailedCheck::Block(FailedBlockCheck { check_id, .. }) => check_id as u64,
                    FailedCheck::Verifier(FailedVerifierCheck { check_id, .. }) => check_id as u64,
                }
            }
        }
        _ => u64::MAX,
    })
}

#[no_mangle]
pub extern "C" fn error_check_block_id(check_index: u64) -> u64 {
    use crate::error::*;
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(Error::Biscuit(Token::FailedLogic(Logic::FailedChecks(ref v)))) => {
            if check_index >= v.len() as u64 {
                u64::MAX
            } else {
                match v[check_index as usize] {
                    FailedCheck::Block(FailedBlockCheck { block_id, .. }) => block_id as u64,
                    _ => u64::MAX,
                }
            }
        }
        _ => u64::MAX,
    })
}

/// deallocation is handled by Biscuit
/// the string is overwritten on each call
#[no_mangle]
pub extern "C" fn error_check_rule(check_index: u64) -> *const c_char {
    use crate::error::*;
    thread_local! {
        static CAVEAT_RULE: RefCell<Option<CString>> = RefCell::new(None);
    }

    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(Error::Biscuit(Token::FailedLogic(Logic::FailedChecks(ref v)))) => {
            if check_index >= v.len() as u64 {
                std::ptr::null()
            } else {
                let rule = match &v[check_index as usize] {
                    FailedCheck::Block(FailedBlockCheck { rule, .. }) => rule,
                    FailedCheck::Verifier(FailedVerifierCheck { rule, .. }) => rule,
                };
                let err = CString::new(rule.clone()).ok();
                CAVEAT_RULE.with(|ret| {
                    *ret.borrow_mut() = err;
                    ret.borrow()
                        .as_ref()
                        .map(|x| x.as_ptr())
                        .unwrap_or(std::ptr::null())
                })
            }
        }
        _ => std::ptr::null(),
    })
}

#[no_mangle]
pub extern "C" fn error_check_is_verifier(check_index: u64) -> bool {
    use crate::error::*;
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(Error::Biscuit(Token::FailedLogic(Logic::FailedChecks(ref v)))) => {
            if check_index >= v.len() as u64 {
                false
            } else {
                match v[check_index as usize] {
                    FailedCheck::Block(FailedBlockCheck { .. }) => false,
                    FailedCheck::Verifier(FailedVerifierCheck { .. }) => true,
                }
            }
        }
        _ => false,
    })
}

pub struct Biscuit(crate::token::Biscuit);
pub struct KeyPair(crate::crypto::KeyPair);
pub struct PublicKey(crate::crypto::PublicKey);
pub struct BiscuitBuilder<'a>(crate::token::builder::BiscuitBuilder<'a>);
pub struct BlockBuilder(crate::token::builder::BlockBuilder);
pub struct Verifier(crate::token::verifier::Verifier);

#[no_mangle]
pub unsafe extern "C" fn key_pair_new<'a>(
    seed_ptr: *const u8,
    seed_len: usize,
) -> Option<Box<KeyPair>> {
    let slice = std::slice::from_raw_parts(seed_ptr, seed_len);
    if slice.len() != 32 {
        update_last_error(Error::InvalidArgument);
        return None;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(slice);

    let mut rng: StdRng = SeedableRng::from_seed(seed);

    Some(Box::new(KeyPair(crate::crypto::KeyPair::new_with_rng(
        &mut rng,
    ))))
}

#[no_mangle]
pub unsafe extern "C" fn key_pair_public(kp: Option<&KeyPair>) -> Option<Box<PublicKey>> {
    if kp.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let kp = kp?;

    Some(Box::new(PublicKey((*kp).0.public())))
}

/// expects a 32 byte buffer
#[no_mangle]
pub unsafe extern "C" fn key_pair_serialize(kp: Option<&KeyPair>, buffer_ptr: *mut u8) -> usize {
    if kp.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }
    let kp = kp.unwrap();

    let output_slice = std::slice::from_raw_parts_mut(buffer_ptr, 32);

    output_slice.copy_from_slice(&kp.0.private().to_bytes()[..]);
    32
}

/// expects a 32 byte buffer
#[no_mangle]
pub unsafe extern "C" fn key_pair_deserialize(buffer_ptr: *mut u8) -> Option<Box<KeyPair>> {
    let input_slice = std::slice::from_raw_parts_mut(buffer_ptr, 32);

    match crate::crypto::PrivateKey::from_bytes(input_slice) {
        None => {
            update_last_error(Error::InvalidArgument);
            None
        }
        Some(privkey) => Some(Box::new(KeyPair(crate::crypto::KeyPair::from(privkey)))),
    }
}

#[no_mangle]
pub unsafe extern "C" fn key_pair_free(_kp: Option<Box<KeyPair>>) {}

/// expects a 32 byte buffer
#[no_mangle]
pub unsafe extern "C" fn public_key_serialize(
    kp: Option<&PublicKey>,
    buffer_ptr: *mut u8,
) -> usize {
    if kp.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }
    let kp = kp.unwrap();

    let output_slice = std::slice::from_raw_parts_mut(buffer_ptr, 32);

    output_slice.copy_from_slice(&kp.0.to_bytes()[..]);
    32
}

/// expects a 32 byte buffer
#[no_mangle]
pub unsafe extern "C" fn public_key_deserialize(buffer_ptr: *mut u8) -> Option<Box<PublicKey>> {
    let input_slice = std::slice::from_raw_parts_mut(buffer_ptr, 32);

    match crate::crypto::PublicKey::from_bytes(input_slice) {
        None => {
            update_last_error(Error::InvalidArgument);
            None
        }
        Some(pubkey) => Some(Box::new(PublicKey(pubkey))),
    }
}

#[no_mangle]
pub unsafe extern "C" fn public_key_free(_kp: Option<Box<PublicKey>>) {}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder<'a>(
    key_pair: Option<&'a KeyPair>,
) -> Option<Box<BiscuitBuilder<'a>>> {
    if key_pair.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let key_pair = key_pair?;

    Some(Box::new(BiscuitBuilder(crate::token::Biscuit::builder(
        &key_pair.0,
    ))))
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_set_authority_context<'a>(
    builder: Option<&mut BiscuitBuilder<'a>>,
    context: *const c_char,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    let context = CStr::from_ptr(context);
    let s = context.to_str();
    match s {
        Err(_) => {
            update_last_error(Error::InvalidArgument);
            false
        }
        Ok(context) => {
            builder.0.set_context(context.to_string());
            true
        }
    }
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

    builder
        .0
        .add_authority_fact(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
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

    builder
        .0
        .add_authority_rule(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_add_authority_check<'a>(
    builder: Option<&mut BiscuitBuilder<'a>>,
    check: *const c_char,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    let check = CStr::from_ptr(check);
    let s = check.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    builder
        .0
        .add_authority_check(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_build<'a>(
    builder: Option<&BiscuitBuilder<'a>>,
    seed_ptr: *const u8,
    seed_len: usize,
) -> Option<Box<Biscuit>> {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let builder = builder?;

    let slice = std::slice::from_raw_parts(seed_ptr, seed_len);
    if slice.len() != 32 {
        return None;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(slice);

    let mut rng: StdRng = SeedableRng::from_seed(seed);
    (*builder)
        .0
        .clone()
        .build_with_rng(&mut rng)
        .map(Biscuit)
        .map(Box::new)
        .ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_free<'a>(_builder: Option<Box<BiscuitBuilder<'a>>>) {}

#[no_mangle]
pub unsafe extern "C" fn biscuit_from(
    biscuit_ptr: *const u8,
    biscuit_len: usize,
) -> Option<Box<Biscuit>> {
    let biscuit = std::slice::from_raw_parts(biscuit_ptr, biscuit_len);

    crate::token::Biscuit::from(biscuit)
        .map(Biscuit)
        .map(Box::new)
        .ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_from_sealed(
    biscuit_ptr: *const u8,
    biscuit_len: usize,
    secret_ptr: *const u8,
    secret_len: usize,
) -> Option<Box<Biscuit>> {
    let biscuit = std::slice::from_raw_parts(biscuit_ptr, biscuit_len);
    let secret = std::slice::from_raw_parts(secret_ptr, secret_len);

    crate::token::Biscuit::from_sealed(biscuit, secret)
        .map(Biscuit)
        .map(Box::new)
        .ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_serialized_size(biscuit: Option<&Biscuit>) -> usize {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }

    let biscuit = biscuit.unwrap();

    match biscuit.0.serialized_size() {
        Ok(sz) => sz,
        Err(e) => {
            update_last_error(Error::Biscuit(e));
            return 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_sealed_size(biscuit: Option<&Biscuit>) -> usize {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }

    let biscuit = biscuit.unwrap();

    match biscuit.0.sealed_size() {
        Ok(sz) => sz,
        Err(e) => {
            update_last_error(Error::Biscuit(e));
            return 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_serialize(
    biscuit: Option<&Biscuit>,
    buffer_ptr: *mut u8,
) -> usize {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }

    let biscuit = biscuit.unwrap();

    match (*biscuit).0.to_vec() {
        Ok(v) => {
            let size = match biscuit.0.serialized_size() {
                Ok(sz) => sz,
                Err(e) => {
                    update_last_error(Error::Biscuit(e));
                    return 0;
                }
            };

            let output_slice = std::slice::from_raw_parts_mut(buffer_ptr, size);

            output_slice.copy_from_slice(&v[..]);
            v.len()
        }
        Err(e) => {
            update_last_error(Error::Biscuit(e));
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_serialize_sealed(
    biscuit: Option<&Biscuit>,
    secret_ptr: *const u8,
    secret_len: usize,
    buffer_ptr: *mut u8,
) -> usize {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }

    let biscuit = biscuit.unwrap();
    let secret = std::slice::from_raw_parts(secret_ptr, secret_len);

    match (*biscuit).0.seal(secret) {
        Ok(v) => {
            let size = match biscuit.0.serialized_size() {
                Ok(sz) => sz,
                Err(e) => {
                    update_last_error(Error::Biscuit(e));
                    return 0;
                }
            };

            let output_slice = std::slice::from_raw_parts_mut(buffer_ptr, size);

            output_slice.copy_from_slice(&v[..]);
            v.len()
        }
        Err(e) => {
            update_last_error(Error::Biscuit(e));
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_block_count(biscuit: Option<&Biscuit>) -> usize {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }

    let biscuit = biscuit.unwrap();

    biscuit.0.blocks.len() + 1
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_block_fact_count(
    biscuit: Option<&Biscuit>,
    block_index: u32,
) -> usize {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }

    let biscuit = biscuit.unwrap();

    if block_index == 0 {
        biscuit.0.authority.facts.len()
    } else {
        match biscuit.0.blocks.get(block_index as usize - 1) {
            Some(b) => b.facts.len(),
            None => {
                update_last_error(Error::InvalidArgument);
                return 0;
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_block_rule_count(
    biscuit: Option<&Biscuit>,
    block_index: u32,
) -> usize {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }

    let biscuit = biscuit.unwrap();

    if block_index == 0 {
        biscuit.0.authority.rules.len()
    } else {
        match biscuit.0.blocks.get(block_index as usize - 1) {
            Some(b) => b.rules.len(),
            None => {
                update_last_error(Error::InvalidArgument);
                return 0;
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_block_check_count(
    biscuit: Option<&Biscuit>,
    block_index: u32,
) -> usize {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }

    let biscuit = biscuit.unwrap();

    if block_index == 0 {
        biscuit.0.authority.checks.len()
    } else {
        match biscuit.0.blocks.get(block_index as usize - 1) {
            Some(b) => b.checks.len(),
            None => {
                update_last_error(Error::InvalidArgument);
                return 0;
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_block_fact(
    biscuit: Option<&Biscuit>,
    block_index: u32,
    fact_index: u32,
) -> *mut c_char {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return std::ptr::null_mut();
    }

    let biscuit = biscuit.unwrap();

    let block = if block_index == 0 {
        &biscuit.0.authority
    } else {
        match biscuit.0.blocks.get(block_index as usize - 1) {
            Some(b) => b,
            None => {
                update_last_error(Error::InvalidArgument);
                return std::ptr::null_mut();
            }
        }
    };

    match block.facts.get(fact_index as usize) {
        None => {
            update_last_error(Error::InvalidArgument);
            return std::ptr::null_mut();
        }
        Some(fact) => match CString::new(biscuit.0.symbols.print_fact(fact)) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                update_last_error(Error::InvalidArgument);
                return std::ptr::null_mut();
            }
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_block_rule(
    biscuit: Option<&Biscuit>,
    block_index: u32,
    rule_index: u32,
) -> *mut c_char {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return std::ptr::null_mut();
    }

    let biscuit = biscuit.unwrap();

    let block = if block_index == 0 {
        &biscuit.0.authority
    } else {
        match biscuit.0.blocks.get(block_index as usize - 1) {
            Some(b) => b,
            None => {
                update_last_error(Error::InvalidArgument);
                return std::ptr::null_mut();
            }
        }
    };

    match block.rules.get(rule_index as usize) {
        None => {
            update_last_error(Error::InvalidArgument);
            return std::ptr::null_mut();
        }
        Some(rule) => match CString::new(biscuit.0.symbols.print_rule(rule)) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                update_last_error(Error::InvalidArgument);
                return std::ptr::null_mut();
            }
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_block_check(
    biscuit: Option<&Biscuit>,
    block_index: u32,
    check_index: u32,
) -> *mut c_char {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return std::ptr::null_mut();
    }

    let biscuit = biscuit.unwrap();

    let block = if block_index == 0 {
        &biscuit.0.authority
    } else {
        match biscuit.0.blocks.get(block_index as usize - 1) {
            Some(b) => b,
            None => {
                update_last_error(Error::InvalidArgument);
                return std::ptr::null_mut();
            }
        }
    };

    match block.checks.get(check_index as usize) {
        None => {
            update_last_error(Error::InvalidArgument);
            return std::ptr::null_mut();
        }
        Some(check) => match CString::new(biscuit.0.symbols.print_check(check)) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                update_last_error(Error::InvalidArgument);
                return std::ptr::null_mut();
            }
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_block_context(
    biscuit: Option<&Biscuit>,
    block_index: u32,
) -> *mut c_char {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return std::ptr::null_mut();
    }

    let biscuit = biscuit.unwrap();

    let block = if block_index == 0 {
        &biscuit.0.authority
    } else {
        match biscuit.0.blocks.get(block_index as usize - 1) {
            Some(b) => b,
            None => {
                update_last_error(Error::InvalidArgument);
                return std::ptr::null_mut();
            }
        }
    };

    match &block.context {
        None => {
            return std::ptr::null_mut();
        }
        Some(context) => match CString::new(context.clone()) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                update_last_error(Error::InvalidArgument);
                return std::ptr::null_mut();
            }
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_create_block(
    biscuit: Option<&Biscuit>,
) -> Option<Box<BlockBuilder>> {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let biscuit = biscuit?;

    Some(Box::new(BlockBuilder(biscuit.0.create_block())))
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_append_block(
    biscuit: Option<&Biscuit>,
    block_builder: Option<&BlockBuilder>,
    key_pair: Option<&KeyPair>,
    seed_ptr: *const u8,
    seed_len: usize,
) -> Option<Box<Biscuit>> {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let biscuit = biscuit?;

    if block_builder.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let builder = block_builder?;

    if key_pair.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let key_pair = key_pair?;

    let slice = std::slice::from_raw_parts(seed_ptr, seed_len);
    if slice.len() != 32 {
        update_last_error(Error::InvalidArgument);
        return None;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(slice);

    let mut rng: StdRng = SeedableRng::from_seed(seed);

    match biscuit
        .0
        .append_with_rng(&mut rng, &key_pair.0, builder.0.clone())
    {
        Ok(token) => Some(Box::new(Biscuit(token))),
        Err(e) => {
            update_last_error(Error::Biscuit(e));
            None
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_verify<'a, 'b>(
    biscuit: Option<&'a Biscuit>,
    root: Option<&'b PublicKey>,
) -> Option<Box<Verifier>> {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let biscuit = biscuit?;
    if root.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let root = root?;

    (*biscuit)
        .0
        .verify((*root).0)
        .map(Verifier)
        .map(Box::new)
        .ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_free(_biscuit: Option<Box<Biscuit>>) {}

#[no_mangle]
pub unsafe extern "C" fn block_builder_set_context(
    builder: Option<&mut BlockBuilder>,
    context: *const c_char,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    let context = CStr::from_ptr(context);
    let s = context.to_str();
    match s {
        Err(_) => {
            update_last_error(Error::InvalidArgument);
            false
        }
        Ok(context) => {
            builder.0.set_context(context.to_string());
            true
        }
    }
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

    builder
        .0
        .add_fact(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
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

    builder
        .0
        .add_rule(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn block_builder_add_check(
    builder: Option<&mut BlockBuilder>,
    check: *const c_char,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    let check = CStr::from_ptr(check);
    let s = check.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    builder
        .0
        .add_check(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn block_builder_free(_builder: Option<Box<BlockBuilder>>) {}

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

    verifier
        .0
        .add_fact(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
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

    verifier
        .0
        .add_rule(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn verifier_add_check(
    verifier: Option<&mut Verifier>,
    check: *const c_char,
) -> bool {
    if verifier.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let verifier = verifier.unwrap();

    let check = CStr::from_ptr(check);
    let s = check.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    verifier
        .0
        .add_check(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn verifier_verify(verifier: Option<&mut Verifier>) -> bool {
    if verifier.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let verifier = verifier.unwrap();

    match verifier.0.verify() {
        Ok(_index) => true,
        Err(e) => {
            update_last_error(Error::Biscuit(e));
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn verifier_print(verifier: Option<&mut Verifier>) -> *mut c_char {
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
pub unsafe extern "C" fn verifier_free(_verifier: Option<Box<Verifier>>) {}

#[no_mangle]
pub unsafe extern "C" fn string_free(ptr: *mut c_char) {
    if ptr != std::ptr::null_mut() {
        CString::from_raw(ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_print(biscuit: Option<&Biscuit>) -> *const c_char {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return std::ptr::null();
    }
    let biscuit = biscuit.unwrap();

    match CString::new(biscuit.0.print()) {
        Ok(s) => s.into_raw(),
        Err(_) => {
            update_last_error(Error::InvalidArgument);
            return std::ptr::null();
        }
    }
}
