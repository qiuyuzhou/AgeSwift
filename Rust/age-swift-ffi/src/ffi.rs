//! The C ABI boundary.
//!
//! Safety rules enforced here:
//! - No panic ever crosses the boundary: every entry point wraps its body in
//!   `catch_unwind` and reports `AgeswiftStatus::Panic` instead.
//! - All Rust-allocated memory handed to Swift is released only through
//!   `ageswift_free_bytes` / `ageswift_free_string`, reconstructing the
//!   original Rust allocation.
//! - Input pointers are treated as borrowed for the duration of the call;
//!   null and zero-length cases are handled explicitly.
//! - Error strings are produced only from internal `CoreError` values and
//!   never contain key material, passphrases, or plaintext.

// The entry points below take raw pointers by design: they are C ABI
// functions whose pointer contracts are documented in
// include/age_swift_ffi.h and upheld by the Swift layer. Clippy's
// `not_unsafe_ptr_arg_deref` lint targets Rust callers, which do not exist
// here (the integration tests deliberately exercise the same contracts).
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::api;
use crate::error::CoreError;

/// Mirrors `ageswift_status` in include/age_swift_ffi.h.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgeswiftStatus {
    Ok = 0,
    InvalidArgument = 1,
    InvalidIdentity = 2,
    InvalidRecipient = 3,
    EncryptionFailed = 4,
    DecryptionFailed = 5,
    NoMatchingKey = 6,
    InvalidFormat = 7,
    Panic = 8,
}

/// Mirrors `ageswift_bytes` in include/age_swift_ffi.h.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AgeswiftBytes {
    pub ptr: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

/// Mirrors `ageswift_format` in include/age_swift_ffi.h.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgeswiftFormat {
    Binary = 0,
    AsciiArmor = 1,
}

/// Maps the C ABI format onto the age crate's own format enum. The Rust
/// enum is `repr(C)`; per the header contract callers pass only the two
/// documented discriminants.
fn armor_format(format: AgeswiftFormat) -> age::armor::Format {
    match format {
        AgeswiftFormat::Binary => age::armor::Format::Binary,
        AgeswiftFormat::AsciiArmor => age::armor::Format::AsciiArmor,
    }
}

impl CoreError {
    fn status(&self) -> AgeswiftStatus {
        match self {
            Self::InvalidArgument(_) => AgeswiftStatus::InvalidArgument,
            Self::InvalidIdentity => AgeswiftStatus::InvalidIdentity,
            Self::InvalidRecipient => AgeswiftStatus::InvalidRecipient,
            Self::EncryptionFailed(_) => AgeswiftStatus::EncryptionFailed,
            Self::DecryptionFailed(_) => AgeswiftStatus::DecryptionFailed,
            Self::NoMatchingKey => AgeswiftStatus::NoMatchingKey,
            Self::InvalidFormat(_) => AgeswiftStatus::InvalidFormat,
        }
    }
}

/// Runs `body` behind the panic barrier and converts its result into a
/// status code, writing a message to `error_out` (if non-null) on failure.
fn ffi_boundary<F>(error_out: *mut *mut c_char, body: F) -> AgeswiftStatus
where
    F: FnOnce() -> Result<AgeswiftStatus, CoreError>,
{
    if !error_out.is_null() {
        // SAFETY: `error_out` is a valid out-param provided by the caller.
        unsafe { *error_out = ptr::null_mut() };
    }
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(status)) => status,
        Ok(Err(err)) => {
            write_error_message(error_out, &err.to_string());
            err.status()
        }
        Err(_panic) => {
            write_error_message(
                error_out,
                "an unexpected internal error occurred in the age backend",
            );
            AgeswiftStatus::Panic
        }
    }
}

fn write_error_message(error_out: *mut *mut c_char, message: &str) {
    if error_out.is_null() {
        return;
    }
    // `CoreError` messages are built from static text and `age` error
    // displays, which cannot contain interior NUL bytes; fall back to a
    // constant if one ever appears.
    let cstring = CString::new(message)
        .unwrap_or_else(|_| CString::new("invalid error message").expect("static text"));
    // SAFETY: `error_out` is a valid out-param provided by the caller.
    unsafe { *error_out = cstring.into_raw() };
}

/// Moves a Rust `Vec<u8>` into an `AgeswiftBytes` out-param, transferring
/// ownership of the allocation to the caller.
fn write_bytes_out(vec: Vec<u8>, out: *mut AgeswiftBytes) -> Result<AgeswiftStatus, CoreError> {
    if out.is_null() {
        return Err(CoreError::InvalidArgument("output pointer is null"));
    }
    let mut vec = vec;
    let header = AgeswiftBytes {
        ptr: vec.as_mut_ptr(),
        len: vec.len(),
        capacity: vec.capacity(),
    };
    std::mem::forget(vec);
    // SAFETY: `out` is a valid out-param provided by the caller.
    unsafe { *out = header };
    Ok(AgeswiftStatus::Ok)
}

/// Moves a Rust `String` into a `char **` out-param, transferring ownership.
fn write_string_out(string: String, out: *mut *mut c_char) -> Result<AgeswiftStatus, CoreError> {
    if out.is_null() {
        return Err(CoreError::InvalidArgument("output pointer is null"));
    }
    let cstring = CString::new(string)
        .map_err(|_| CoreError::InvalidArgument("string contains interior NUL byte"))?;
    // SAFETY: `out` is a valid out-param provided by the caller.
    unsafe { *out = cstring.into_raw() };
    Ok(AgeswiftStatus::Ok)
}

/// Borrowed slice from an FFI input buffer.
///
/// # Safety
/// `ptr` must point to `len` initialized bytes (or be null when `len` is 0)
/// and stay valid for the duration of the call.
unsafe fn input_bytes(ptr: *const u8, len: usize) -> Result<&'static [u8], CoreError> {
    if len == 0 {
        Ok(&[])
    } else if ptr.is_null() {
        Err(CoreError::InvalidArgument(
            "buffer pointer is null but length is nonzero",
        ))
    } else {
        // SAFETY: caller guarantees validity for the call's duration; the
        // borrow never escapes the FFI entry point.
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}

/// Borrowed UTF-8 string from an FFI input.
///
/// # Safety
/// `ptr` must be null-terminated valid UTF-8 (or null).
unsafe fn input_str<'a>(ptr: *const c_char, what: &'static str) -> Result<&'a str, CoreError> {
    if ptr.is_null() {
        return Err(CoreError::InvalidArgument(what));
    }
    // SAFETY: caller guarantees a NUL-terminated string.
    let bytes = unsafe { CStr::from_ptr(ptr) };
    bytes
        .to_str()
        .map_err(|_| CoreError::InvalidArgument("string is not valid UTF-8"))
}

/// Borrowed list of UTF-8 strings from an FFI array-of-pointers input.
///
/// # Safety
/// `items` must point to `len` pointers, each null-terminated valid UTF-8.
unsafe fn input_str_list<'a>(
    items: *const *const c_char,
    len: usize,
    what: &'static str,
) -> Result<Vec<&'a str>, CoreError> {
    if len == 0 {
        return Err(CoreError::InvalidArgument(what));
    }
    if items.is_null() {
        return Err(CoreError::InvalidArgument("string array pointer is null"));
    }
    let mut out = Vec::with_capacity(len);
    for index in 0..len {
        // SAFETY: caller guarantees `len` valid pointers.
        let item = unsafe { *items.add(index) };
        out.push(unsafe { input_str(item, "string array contains a null entry")? });
    }
    Ok(out)
}

#[no_mangle]
pub extern "C" fn ageswift_ffi_version() -> *const c_char {
    // Points into static rodata; documented in the header as not freed.
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn ageswift_generate_identity(
    identity_out: *mut *mut c_char,
    recipient_out: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> AgeswiftStatus {
    ffi_boundary(error_out, || {
        let generated = api::generate_identity();
        write_string_out(generated.identity, identity_out)?;
        write_string_out(generated.recipient, recipient_out)?;
        Ok(AgeswiftStatus::Ok)
    })
}

#[no_mangle]
pub extern "C" fn ageswift_validate_identity(
    identity: *const c_char,
    error_out: *mut *mut c_char,
) -> AgeswiftStatus {
    ffi_boundary(error_out, || {
        // SAFETY: caller of the C ABI honors the pointer contract.
        let string = unsafe { input_str(identity, "identity string pointer is null")? };
        api::parse_identity(string).map(|_| AgeswiftStatus::Ok)
    })
}

#[no_mangle]
pub extern "C" fn ageswift_validate_recipient(
    recipient: *const c_char,
    error_out: *mut *mut c_char,
) -> AgeswiftStatus {
    ffi_boundary(error_out, || {
        // SAFETY: caller of the C ABI honors the pointer contract.
        let string = unsafe { input_str(recipient, "recipient string pointer is null")? };
        api::parse_recipient(string).map(|_| AgeswiftStatus::Ok)
    })
}

#[no_mangle]
pub extern "C" fn ageswift_identity_recipient(
    identity: *const c_char,
    recipient_out: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> AgeswiftStatus {
    ffi_boundary(error_out, || {
        // SAFETY: caller of the C ABI honors the pointer contract.
        let string = unsafe { input_str(identity, "identity string pointer is null")? };
        let parsed = api::parse_identity(string)?;
        write_string_out(api::identity_recipient(&parsed), recipient_out)?;
        Ok(AgeswiftStatus::Ok)
    })
}

#[no_mangle]
pub extern "C" fn ageswift_encrypt_to_recipients(
    plaintext: *const u8,
    plaintext_len: usize,
    recipients: *const *const c_char,
    recipients_len: usize,
    format: AgeswiftFormat,
    ciphertext_out: *mut AgeswiftBytes,
    error_out: *mut *mut c_char,
) -> AgeswiftStatus {
    ffi_boundary(error_out, || {
        // SAFETY: caller of the C ABI honors the pointer contract.
        let plaintext = unsafe { input_bytes(plaintext, plaintext_len)? };
        // SAFETY: caller of the C ABI honors the pointer contract.
        let recipient_strings = unsafe {
            input_str_list(
                recipients,
                recipients_len,
                "at least one recipient is required",
            )?
        };
        let parsed = recipient_strings
            .iter()
            .map(|s| api::parse_recipient(s))
            .collect::<Result<Vec<_>, _>>()?;
        let ciphertext = api::encrypt_to_recipients(plaintext, &parsed, armor_format(format))?;
        write_bytes_out(ciphertext, ciphertext_out)
    })
}

#[no_mangle]
pub extern "C" fn ageswift_encrypt_with_passphrase(
    plaintext: *const u8,
    plaintext_len: usize,
    passphrase: *const c_char,
    format: AgeswiftFormat,
    ciphertext_out: *mut AgeswiftBytes,
    error_out: *mut *mut c_char,
) -> AgeswiftStatus {
    ffi_boundary(error_out, || {
        // SAFETY: caller of the C ABI honors the pointer contract.
        let plaintext = unsafe { input_bytes(plaintext, plaintext_len)? };
        // SAFETY: caller of the C ABI honors the pointer contract.
        let passphrase = unsafe { input_str(passphrase, "passphrase pointer is null")? };
        let ciphertext = api::encrypt_with_passphrase(plaintext, passphrase, armor_format(format))?;
        write_bytes_out(ciphertext, ciphertext_out)
    })
}

#[no_mangle]
pub extern "C" fn ageswift_decrypt_with_identities(
    ciphertext: *const u8,
    ciphertext_len: usize,
    identities: *const *const c_char,
    identities_len: usize,
    plaintext_out: *mut AgeswiftBytes,
    error_out: *mut *mut c_char,
) -> AgeswiftStatus {
    ffi_boundary(error_out, || {
        // SAFETY: caller of the C ABI honors the pointer contract.
        let ciphertext = unsafe { input_bytes(ciphertext, ciphertext_len)? };
        // SAFETY: caller of the C ABI honors the pointer contract.
        let identity_strings = unsafe {
            input_str_list(
                identities,
                identities_len,
                "at least one identity is required",
            )?
        };
        let parsed = identity_strings
            .iter()
            .map(|s| api::parse_identity(s))
            .collect::<Result<Vec<_>, _>>()?;
        let plaintext = api::decrypt_with_identities(ciphertext, &parsed)?;
        write_bytes_out(plaintext, plaintext_out)
    })
}

#[no_mangle]
pub extern "C" fn ageswift_decrypt_with_passphrase(
    ciphertext: *const u8,
    ciphertext_len: usize,
    passphrase: *const c_char,
    plaintext_out: *mut AgeswiftBytes,
    error_out: *mut *mut c_char,
) -> AgeswiftStatus {
    ffi_boundary(error_out, || {
        // SAFETY: caller of the C ABI honors the pointer contract.
        let ciphertext = unsafe { input_bytes(ciphertext, ciphertext_len)? };
        // SAFETY: caller of the C ABI honors the pointer contract.
        let passphrase = unsafe { input_str(passphrase, "passphrase pointer is null")? };
        let plaintext = api::decrypt_with_passphrase(ciphertext, passphrase)?;
        write_bytes_out(plaintext, plaintext_out)
    })
}

#[no_mangle]
pub extern "C" fn ageswift_armor(
    binary: *const u8,
    binary_len: usize,
    armored_out: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> AgeswiftStatus {
    ffi_boundary(error_out, || {
        // SAFETY: caller of the C ABI honors the pointer contract.
        let binary = unsafe { input_bytes(binary, binary_len)? };
        let armored = api::armor(binary)?;
        write_string_out(armored, armored_out)
    })
}

#[no_mangle]
pub extern "C" fn ageswift_dearmor(
    armored: *const c_char,
    binary_out: *mut AgeswiftBytes,
    error_out: *mut *mut c_char,
) -> AgeswiftStatus {
    ffi_boundary(error_out, || {
        // SAFETY: caller of the C ABI honors the pointer contract.
        let armored = unsafe { input_str(armored, "armored input pointer is null")? };
        let binary = api::dearmor(armored)?;
        write_bytes_out(binary, binary_out)
    })
}

#[no_mangle]
pub extern "C" fn ageswift_free_bytes(buffer: AgeswiftBytes) {
    if buffer.ptr.is_null() {
        return;
    }
    // SAFETY: the buffer was produced by `write_bytes_out` from a `Vec` with
    // exactly this pointer, length, and capacity, and is released exactly
    // once by the Swift caller.
    unsafe {
        drop(Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.capacity));
    }
}

#[no_mangle]
pub extern "C" fn ageswift_free_string(string: *mut c_char) {
    if string.is_null() {
        return;
    }
    // SAFETY: the string was produced by `CString::into_raw` in
    // `write_string_out` / `write_error_message`, and is released exactly
    // once by the Swift caller.
    unsafe { drop(CString::from_raw(string)) };
}
