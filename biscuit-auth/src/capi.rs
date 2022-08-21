use rand::prelude::*;
use std::{
    cell::RefCell,
    ffi::{CStr, CString},
    fmt,
    os::raw::c_char,
};

use crate::datalog::SymbolTable;

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

impl From<crate::error::Token> for Error {
    fn from(error: crate::error::Token) -> Self {
        Error::Biscuit(error)
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
    FormatUnknownPublicKey,
    FormatDeserializationError,
    FormatSerializationError,
    FormatBlockDeserializationError,
    FormatBlockSerializationError,
    FormatVersion,
    FormatInvalidBlockId,
    FormatExistingPublicKey,
    FormatSymbolTableOverlap,
    FormatPublicKeyTableOverlap,
    FormatUnknownExternalKey,
    FormatUnknownSymbol,
    AppendOnSealed,
    LogicInvalidBlockRule,
    LogicUnauthorized,
    LogicAuthorizerNotEmpty,
    LogicNoMatchingPolicy,
    LanguageError,
    TooManyFacts,
    TooManyIterations,
    Timeout,
    ConversionError,
    FormatInvalidKeySize,
    FormatInvalidSignatureSize,
    FormatInvalidKey,
    FormatSignatureDeserializationError,
    FormatBlockSignatureDeserializationError,
    FormatSignatureInvalidSignatureGeneration,
    AlreadySealed,
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
                    Token::Format(Format::Signature(Signature::InvalidSignature(_))) => {
                        ErrorKind::FormatSignatureInvalidSignature
                    }
                    Token::Format(Format::Signature(Signature::InvalidSignatureGeneration(_))) => {
                        ErrorKind::FormatSignatureInvalidSignatureGeneration
                    }
                    Token::Format(Format::SealedSignature) => ErrorKind::FormatSealedSignature,
                    Token::Format(Format::EmptyKeys) => ErrorKind::FormatEmptyKeys,
                    Token::Format(Format::UnknownPublicKey) => ErrorKind::FormatUnknownPublicKey,
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
                    Token::Format(Format::InvalidKeySize(_)) => ErrorKind::FormatInvalidKeySize,
                    Token::Format(Format::InvalidSignatureSize(_)) => {
                        ErrorKind::FormatInvalidSignatureSize
                    }
                    Token::Format(Format::InvalidKey(_)) => ErrorKind::FormatInvalidKey,
                    Token::Format(Format::SignatureDeserializationError(_)) => {
                        ErrorKind::FormatSignatureDeserializationError
                    }
                    Token::Format(Format::BlockSignatureDeserializationError(_)) => {
                        ErrorKind::FormatBlockSignatureDeserializationError
                    }
                    Token::Format(Format::InvalidBlockId(_)) => ErrorKind::FormatInvalidBlockId,
                    Token::Format(Format::ExistingPublicKey(_)) => {
                        ErrorKind::FormatExistingPublicKey
                    }
                    Token::Format(Format::SymbolTableOverlap) => {
                        ErrorKind::FormatSymbolTableOverlap
                    }
                    Token::Format(Format::PublicKeyTableOverlap) => {
                        ErrorKind::FormatPublicKeyTableOverlap
                    }
                    Token::Format(Format::UnknownExternalKey) => {
                        ErrorKind::FormatUnknownExternalKey
                    }
                    Token::Format(Format::UnknownSymbol(_)) => ErrorKind::FormatUnknownSymbol,
                    Token::AppendOnSealed => ErrorKind::AppendOnSealed,
                    Token::AlreadySealed => ErrorKind::AlreadySealed,
                    Token::Language(_) => ErrorKind::LanguageError,
                    Token::FailedLogic(Logic::InvalidBlockRule(_, _)) => {
                        ErrorKind::LogicInvalidBlockRule
                    }
                    Token::FailedLogic(Logic::Unauthorized { .. }) => ErrorKind::LogicUnauthorized,
                    Token::FailedLogic(Logic::AuthorizerNotEmpty) => {
                        ErrorKind::LogicAuthorizerNotEmpty
                    }
                    Token::FailedLogic(Logic::NoMatchingPolicy { .. }) => {
                        ErrorKind::LogicNoMatchingPolicy
                    }
                    Token::RunLimit(RunLimit::TooManyFacts) => ErrorKind::TooManyFacts,
                    Token::RunLimit(RunLimit::TooManyIterations) => ErrorKind::TooManyIterations,
                    Token::RunLimit(RunLimit::Timeout) => ErrorKind::Timeout,
                    Token::ConversionError(_) => ErrorKind::ConversionError,
                    Token::Base64(_) => ErrorKind::FormatDeserializationError,
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
        Some(Error::Biscuit(Token::FailedLogic(Logic::Unauthorized { ref checks, .. })))
        | Some(Error::Biscuit(Token::FailedLogic(Logic::NoMatchingPolicy { ref checks }))) => {
            checks.len() as u64
        }
        _ => 0,
    })
}

#[no_mangle]
pub extern "C" fn error_check_id(check_index: u64) -> u64 {
    use crate::error::*;
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(Error::Biscuit(Token::FailedLogic(Logic::Unauthorized { ref checks, .. })))
        | Some(Error::Biscuit(Token::FailedLogic(Logic::NoMatchingPolicy { ref checks }))) => {
            if check_index >= checks.len() as u64 {
                u64::MAX
            } else {
                match checks[check_index as usize] {
                    FailedCheck::Block(FailedBlockCheck { check_id, .. }) => check_id as u64,
                    FailedCheck::Authorizer(FailedAuthorizerCheck { check_id, .. }) => {
                        check_id as u64
                    }
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
        Some(Error::Biscuit(Token::FailedLogic(Logic::Unauthorized { ref checks, .. })))
        | Some(Error::Biscuit(Token::FailedLogic(Logic::NoMatchingPolicy { ref checks }))) => {
            if check_index >= checks.len() as u64 {
                u64::MAX
            } else {
                match checks[check_index as usize] {
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
        Some(Error::Biscuit(Token::FailedLogic(Logic::Unauthorized { ref checks, .. })))
        | Some(Error::Biscuit(Token::FailedLogic(Logic::NoMatchingPolicy { ref checks }))) => {
            if check_index >= checks.len() as u64 {
                std::ptr::null()
            } else {
                let rule = match &checks[check_index as usize] {
                    FailedCheck::Block(FailedBlockCheck { rule, .. }) => rule,
                    FailedCheck::Authorizer(FailedAuthorizerCheck { rule, .. }) => rule,
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
pub extern "C" fn error_check_is_authorizer(check_index: u64) -> bool {
    use crate::error::*;
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(Error::Biscuit(Token::FailedLogic(Logic::Unauthorized { ref checks, .. })))
        | Some(Error::Biscuit(Token::FailedLogic(Logic::NoMatchingPolicy { ref checks }))) => {
            if check_index >= checks.len() as u64 {
                false
            } else {
                match checks[check_index as usize] {
                    FailedCheck::Block(FailedBlockCheck { .. }) => false,
                    FailedCheck::Authorizer(FailedAuthorizerCheck { .. }) => true,
                }
            }
        }
        _ => false,
    })
}

pub struct Biscuit(crate::token::Biscuit);
pub struct KeyPair(crate::crypto::KeyPair);
pub struct PublicKey(crate::crypto::PublicKey);
pub struct BiscuitBuilder(crate::token::builder::BiscuitBuilder);
pub struct BlockBuilder(crate::token::builder::BlockBuilder);
pub struct Authorizer<'t>(crate::token::authorizer::Authorizer<'t>);

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

    match crate::crypto::PrivateKey::from_bytes(input_slice).ok() {
        None => {
            update_last_error(Error::InvalidArgument);
            None
        }
        Some(privkey) => Some(Box::new(KeyPair(crate::crypto::KeyPair::from(&privkey)))),
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

    match crate::crypto::PublicKey::from_bytes(input_slice).ok() {
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
pub unsafe extern "C" fn biscuit_builder() -> Option<Box<BiscuitBuilder>> {
    Some(Box::new(BiscuitBuilder(crate::token::Biscuit::builder())))
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_set_context(
    builder: Option<&mut BiscuitBuilder>,
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
pub unsafe extern "C" fn biscuit_builder_set_root_key_id(
    builder: Option<&mut BiscuitBuilder>,
    root_key_id: u32,
) -> bool {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let builder = builder.unwrap();

    builder.0.set_root_key_id(root_key_id);
    true
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_add_fact(
    builder: Option<&mut BiscuitBuilder>,
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
pub unsafe extern "C" fn biscuit_builder_add_rule(
    builder: Option<&mut BiscuitBuilder>,
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
pub unsafe extern "C" fn biscuit_builder_add_check(
    builder: Option<&mut BiscuitBuilder>,
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
pub unsafe extern "C" fn biscuit_builder_build(
    builder: Option<&BiscuitBuilder>,
    key_pair: Option<&KeyPair>,
    seed_ptr: *const u8,
    seed_len: usize,
) -> Option<Box<Biscuit>> {
    if builder.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let builder = builder?;

    if key_pair.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let key_pair = key_pair?;

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
        .build_with_rng(&key_pair.0, SymbolTable::default(), &mut rng)
        .map(Biscuit)
        .map(Box::new)
        .ok()
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_builder_free<'a>(_builder: Option<Box<BiscuitBuilder>>) {}

#[no_mangle]
pub unsafe extern "C" fn biscuit_from<'a>(
    biscuit_ptr: *const u8,
    biscuit_len: usize,
    root: Option<&'a PublicKey>,
) -> Option<Box<Biscuit>> {
    let biscuit = std::slice::from_raw_parts(biscuit_ptr, biscuit_len);
    if root.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let root = root?;

    crate::token::Biscuit::from(biscuit, root.0)
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

    match biscuit.0.serialized_size() {
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
    buffer_ptr: *mut u8,
) -> usize {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
        return 0;
    }

    let biscuit = biscuit.unwrap();

    match (*biscuit).0.seal() {
        Ok(b) => match b.to_vec() {
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
        },

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

    let block = match biscuit.0.block(block_index as usize) {
        Ok(block) => block,
        Err(e) => {
            update_last_error(e.into());
            return 0;
        }
    };

    block.facts.len()
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

    let block = match biscuit.0.block(block_index as usize) {
        Ok(block) => block,
        Err(e) => {
            update_last_error(e.into());
            return 0;
        }
    };

    block.rules.len()
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

    let block = match biscuit.0.block(block_index as usize) {
        Ok(block) => block,
        Err(e) => {
            update_last_error(e.into());
            return 0;
        }
    };

    block.checks.len()
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

    let block = match biscuit.0.block(block_index as usize) {
        Ok(block) => block,
        Err(e) => {
            update_last_error(e.into());
            return std::ptr::null_mut();
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

    let block = match biscuit.0.block(block_index as usize) {
        Ok(block) => block,
        Err(e) => {
            update_last_error(e.into());
            return std::ptr::null_mut();
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

    let block = match biscuit.0.block(block_index as usize) {
        Ok(block) => block,
        Err(e) => {
            update_last_error(e.into());
            return std::ptr::null_mut();
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
pub unsafe extern "C" fn create_block() -> Box<BlockBuilder> {
    Box::new(BlockBuilder(crate::token::builder::BlockBuilder::new()))
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_append_block(
    biscuit: Option<&Biscuit>,
    block_builder: Option<&BlockBuilder>,
    key_pair: Option<&KeyPair>,
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

    match biscuit
        .0
        .append_with_keypair(&key_pair.0, builder.0.clone())
    {
        Ok(token) => Some(Box::new(Biscuit(token))),
        Err(e) => {
            update_last_error(Error::Biscuit(e));
            None
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn biscuit_authorizer<'a, 'b>(
    biscuit: Option<&'a Biscuit>,
) -> Option<Box<Authorizer<'a>>> {
    if biscuit.is_none() {
        update_last_error(Error::InvalidArgument);
    }
    let biscuit = biscuit?;

    (*biscuit).0.authorizer().map(Authorizer).map(Box::new).ok()
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
pub unsafe extern "C" fn authorizer_add_fact(
    authorizer: Option<&mut Authorizer>,
    fact: *const c_char,
) -> bool {
    if authorizer.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let authorizer = authorizer.unwrap();

    let fact = CStr::from_ptr(fact);
    let s = fact.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    authorizer
        .0
        .add_fact(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn authorizer_add_rule(
    authorizer: Option<&mut Authorizer>,
    rule: *const c_char,
) -> bool {
    if authorizer.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let authorizer = authorizer.unwrap();

    let rule = CStr::from_ptr(rule);
    let s = rule.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    authorizer
        .0
        .add_rule(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn authorizer_add_check(
    authorizer: Option<&mut Authorizer>,
    check: *const c_char,
) -> bool {
    if authorizer.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let authorizer = authorizer.unwrap();

    let check = CStr::from_ptr(check);
    let s = check.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    authorizer
        .0
        .add_check(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn authorizer_add_policy(
    authorizer: Option<&mut Authorizer>,
    policy: *const c_char,
) -> bool {
    if authorizer.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let authorizer = authorizer.unwrap();

    let policy = CStr::from_ptr(policy);
    let s = policy.to_str();
    if s.is_err() {
        update_last_error(Error::InvalidArgument);
        return false;
    }

    authorizer
        .0
        .add_policy(s.unwrap())
        .map_err(|e| {
            update_last_error(Error::Biscuit(e));
        })
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn authorizer_authorize(authorizer: Option<&mut Authorizer>) -> bool {
    if authorizer.is_none() {
        update_last_error(Error::InvalidArgument);
        return false;
    }
    let authorizer = authorizer.unwrap();

    match authorizer.0.authorize() {
        Ok(_index) => true,
        Err(e) => {
            update_last_error(Error::Biscuit(e));
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn authorizer_print(authorizer: Option<&mut Authorizer>) -> *mut c_char {
    if authorizer.is_none() {
        update_last_error(Error::InvalidArgument);
        return std::ptr::null_mut();
    }
    let authorizer = authorizer.unwrap();

    match CString::new(authorizer.0.print_world()) {
        Ok(s) => s.into_raw(),
        Err(_) => {
            update_last_error(Error::InvalidArgument);
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn authorizer_free(_authorizer: Option<Box<Authorizer>>) {}

#[no_mangle]
pub unsafe extern "C" fn string_free(ptr: *mut c_char) {
    if ptr != std::ptr::null_mut() {
        drop(CString::from_raw(ptr));
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
