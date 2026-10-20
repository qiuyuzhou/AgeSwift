//! FFI-level integration tests: these exercise the C ABI exactly as Swift
//! would, including buffer ownership and null handling.

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use age_swift_ffi::ffi::*;

// ---------------------------------------------------------------- helpers

fn assert_ok(status: AgeswiftStatus, error: *mut c_char) {
    assert_eq!(status, AgeswiftStatus::Ok, "expected Ok, got {status:?}");
    if !error.is_null() {
        ageswift_free_string(error);
    }
}

fn assert_status(expected: AgeswiftStatus, status: AgeswiftStatus, error: *mut c_char) -> String {
    if !error.is_null() {
        let message = unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned();
        ageswift_free_string(error);
        assert_eq!(status, expected, "message: {message}");
        message
    } else {
        assert_eq!(status, expected, "no error message attached");
        String::new()
    }
}

fn take_string(raw: *mut c_char) -> String {
    assert!(!raw.is_null());
    let string = unsafe { CStr::from_ptr(raw) }
        .to_str()
        .expect("valid UTF-8")
        .to_owned();
    ageswift_free_string(raw);
    string
}

/// Copies a Rust-owned buffer out and releases it through the public free
/// function, exercising the ownership path Swift relies on.
fn take_bytes(buffer: AgeswiftBytes) -> Vec<u8> {
    let bytes = if buffer.len == 0 {
        Vec::new()
    } else {
        assert!(!buffer.ptr.is_null());
        unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) }.to_vec()
    };
    ageswift_free_bytes(buffer);
    bytes
}

fn zeroed_bytes() -> AgeswiftBytes {
    AgeswiftBytes {
        ptr: ptr::null_mut(),
        len: 0,
        capacity: 0,
    }
}

fn generate() -> (String, String) {
    let mut identity = ptr::null_mut();
    let mut recipient = ptr::null_mut();
    let mut error = ptr::null_mut();
    let status = ageswift_generate_identity(&mut identity, &mut recipient, &mut error);
    assert_ok(status, error);
    (take_string(identity), take_string(recipient))
}

fn encrypt_to_recipients(plaintext: &[u8], recipients: &[&str]) -> AgeswiftStatus {
    let mut ciphertext = zeroed_bytes();
    let mut error = ptr::null_mut();
    let c_recipients: Vec<CString> = recipients
        .iter()
        .map(|r| CString::new(*r).expect("recipients contain no NUL"))
        .collect();
    let ptrs: Vec<*const c_char> = c_recipients.iter().map(|c| c.as_ptr()).collect();
    let (plain_ptr, plain_len) = if plaintext.is_empty() {
        (ptr::null(), 0)
    } else {
        (plaintext.as_ptr(), plaintext.len())
    };
    let status = ageswift_encrypt_to_recipients(
        plain_ptr,
        plain_len,
        ptrs.as_ptr(),
        ptrs.len(),
        &mut ciphertext,
        &mut error,
    );
    if status == AgeswiftStatus::Ok {
        assert_ok(status, error);
        let bytes = take_bytes(ciphertext);
        assert!(bytes.starts_with(b"age-encryption.org/v1\n"));
    } else {
        assert!(ciphertext.ptr.is_null() && ciphertext.len == 0);
    }
    status
}

fn encrypt_for_assertion(plaintext: &[u8], recipients: &[&str]) -> Vec<u8> {
    let mut ciphertext = zeroed_bytes();
    let mut error = ptr::null_mut();
    let c_recipients: Vec<CString> = recipients
        .iter()
        .map(|r| CString::new(*r).expect("recipients contain no NUL"))
        .collect();
    let ptrs: Vec<*const c_char> = c_recipients.iter().map(|c| c.as_ptr()).collect();
    let (plain_ptr, plain_len) = if plaintext.is_empty() {
        (ptr::null(), 0)
    } else {
        (plaintext.as_ptr(), plaintext.len())
    };
    let status = ageswift_encrypt_to_recipients(
        plain_ptr,
        plain_len,
        ptrs.as_ptr(),
        ptrs.len(),
        &mut ciphertext,
        &mut error,
    );
    assert_ok(status, error);
    take_bytes(ciphertext)
}

fn decrypt_with_identities(
    ciphertext: &[u8],
    identities: &[&str],
) -> Result<Vec<u8>, AgeswiftStatus> {
    let mut plaintext = zeroed_bytes();
    let mut error = ptr::null_mut();
    let c_identities: Vec<CString> = identities
        .iter()
        .map(|i| CString::new(*i).expect("identities contain no NUL"))
        .collect();
    let ptrs: Vec<*const c_char> = c_identities.iter().map(|c| c.as_ptr()).collect();
    let status = ageswift_decrypt_with_identities(
        ciphertext.as_ptr(),
        ciphertext.len(),
        ptrs.as_ptr(),
        ptrs.len(),
        &mut plaintext,
        &mut error,
    );
    if status == AgeswiftStatus::Ok {
        assert_ok(status, error);
        Ok(take_bytes(plaintext))
    } else {
        if !error.is_null() {
            ageswift_free_string(error);
        }
        Err(status)
    }
}

fn encrypt_passphrase_for_assertion(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
    let mut ciphertext = zeroed_bytes();
    let mut error = ptr::null_mut();
    let c_passphrase = CString::new(passphrase).expect("passphrase contains no NUL");
    let status = ageswift_encrypt_with_passphrase(
        plaintext.as_ptr(),
        plaintext.len(),
        c_passphrase.as_ptr(),
        &mut ciphertext,
        &mut error,
    );
    assert_ok(status, error);
    take_bytes(ciphertext)
}

fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>, AgeswiftStatus> {
    let mut plaintext = zeroed_bytes();
    let mut error = ptr::null_mut();
    let c_passphrase = CString::new(passphrase).expect("passphrase contains no NUL");
    let status = ageswift_decrypt_with_passphrase(
        ciphertext.as_ptr(),
        ciphertext.len(),
        c_passphrase.as_ptr(),
        &mut plaintext,
        &mut error,
    );
    if status == AgeswiftStatus::Ok {
        assert_ok(status, error);
        Ok(take_bytes(plaintext))
    } else {
        if !error.is_null() {
            ageswift_free_string(error);
        }
        Err(status)
    }
}

// ------------------------------------------------------------ identity

#[test]
fn version_is_returned() {
    let version = ageswift_ffi_version();
    assert!(!version.is_null());
    let version = unsafe { CStr::from_ptr(version) }.to_str().expect("UTF-8");
    assert!(version.contains("0."));
}

#[test]
fn generated_identity_roundtrips_through_string() {
    let (identity, recipient) = generate();
    assert!(identity.starts_with("AGE-SECRET-KEY-1"));
    assert!(recipient.starts_with("age1"));

    // Validate the identity string, and re-derive the recipient from it.
    let c_identity = CString::new(identity.clone()).unwrap();
    let mut error = ptr::null_mut();
    let status = ageswift_validate_identity(c_identity.as_ptr(), &mut error);
    assert_ok(status, error);

    let mut derived = ptr::null_mut();
    let status = ageswift_identity_recipient(c_identity.as_ptr(), &mut derived, &mut error);
    assert_ok(status, error);
    assert_eq!(take_string(derived), recipient);

    // The recipient string is also a valid recipient.
    let c_recipient = CString::new(recipient).unwrap();
    let status = ageswift_validate_recipient(c_recipient.as_ptr(), &mut error);
    assert_ok(status, error);
}

#[test]
fn invalid_identity_and_recipient_strings_are_rejected() {
    let mut error = ptr::null_mut();

    for bad in ["", "AGE-SECRET-KEY-1NOT-A-REAL-KEY", "age1notakey", "hello"] {
        let c_bad = CString::new(bad).unwrap();
        let status = ageswift_validate_identity(c_bad.as_ptr(), &mut error);
        assert_status(AgeswiftStatus::InvalidIdentity, status, error);

        let status = ageswift_validate_recipient(c_bad.as_ptr(), &mut error);
        assert_status(AgeswiftStatus::InvalidRecipient, status, error);
    }

    // A recipient string is not an identity and vice versa.
    let (identity, recipient) = generate();
    let c_recipient = CString::new(recipient).unwrap();
    let status = ageswift_validate_identity(c_recipient.as_ptr(), &mut error);
    assert_status(AgeswiftStatus::InvalidIdentity, status, error);

    let c_identity = CString::new(identity).unwrap();
    let status = ageswift_validate_recipient(c_identity.as_ptr(), &mut error);
    assert_status(AgeswiftStatus::InvalidRecipient, status, error);
}

#[test]
fn null_string_pointers_are_rejected() {
    let mut error = ptr::null_mut();
    let status = ageswift_validate_identity(ptr::null(), &mut error);
    assert_status(AgeswiftStatus::InvalidArgument, status, error);
    let status = ageswift_validate_recipient(ptr::null(), &mut error);
    assert_status(AgeswiftStatus::InvalidArgument, status, error);
}

// ------------------------------------------------------------ x25519

#[test]
fn x25519_roundtrip() {
    let (identity, recipient) = generate();
    let plaintext = b"hello from the age-swift-ffi tests";
    let ciphertext = encrypt_for_assertion(plaintext, &[&recipient]);
    assert_ne!(&ciphertext[..], &plaintext[..]);
    let decrypted = decrypt_with_identities(&ciphertext, &[&identity]).expect("decrypts");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn x25519_multiple_recipients_each_decrypt() {
    let (identity_a, recipient_a) = generate();
    let (identity_b, recipient_b) = generate();
    let (identity_c, _) = generate(); // not a recipient of this file

    let plaintext = b"multi-recipient payload";
    let ciphertext = encrypt_for_assertion(plaintext, &[&recipient_a, &recipient_b]);

    assert_eq!(
        decrypt_with_identities(&ciphertext, &[&identity_a]).expect("A decrypts"),
        plaintext
    );
    assert_eq!(
        decrypt_with_identities(&ciphertext, &[&identity_b]).expect("B decrypts"),
        plaintext
    );
    // A list containing a non-matching identity still decrypts.
    assert_eq!(
        decrypt_with_identities(&ciphertext, &[&identity_c, &identity_a])
            .expect("mixed list decrypts"),
        plaintext
    );
    // The unrelated identity alone does not.
    assert_eq!(
        decrypt_with_identities(&ciphertext, &[&identity_c]),
        Err(AgeswiftStatus::NoMatchingKey)
    );
}

#[test]
fn x25519_two_encryptions_differ() {
    let (_, recipient) = generate();
    let one = encrypt_for_assertion(b"same message", &[&recipient]);
    let two = encrypt_for_assertion(b"same message", &[&recipient]);
    assert_ne!(one, two, "file keys and ephemeral keys must be random");
}

#[test]
fn x25519_empty_and_binary_plaintext() {
    let (identity, recipient) = generate();

    let empty = encrypt_for_assertion(&[], &[&recipient]);
    assert_eq!(
        decrypt_with_identities(&empty, &[&identity]).expect("empty decrypts"),
        Vec::<u8>::new()
    );

    let binary: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
    let encrypted = encrypt_for_assertion(&binary, &[&recipient]);
    assert_eq!(
        decrypt_with_identities(&encrypted, &[&identity]).expect("binary decrypts"),
        binary
    );
}

// ------------------------------------------------------------ passphrase

#[test]
fn scrypt_roundtrip_and_wrong_passphrase() {
    let plaintext = b"passphrase secret";
    let ciphertext = encrypt_passphrase_for_assertion(plaintext, "correct horse battery staple");

    let decrypted = decrypt_with_passphrase(&ciphertext, "correct horse battery staple")
        .expect("right passphrase decrypts");
    assert_eq!(decrypted, plaintext);

    // A wrong passphrase must not leak plaintext or crash; scrypt work makes
    // this attempt deliberately slow, which is expected.
    assert_eq!(
        decrypt_with_passphrase(&ciphertext, "wrong passphrase"),
        Err(AgeswiftStatus::NoMatchingKey)
    );
}

#[test]
fn scrypt_empty_plaintext() {
    let ciphertext = encrypt_passphrase_for_assertion(&[], "pw");
    assert_eq!(
        decrypt_with_passphrase(&ciphertext, "pw").expect("empty decrypts"),
        Vec::<u8>::new()
    );
}

#[test]
fn passphrase_file_is_not_opened_by_x25519_identities() {
    let (identity, _) = generate();
    let ciphertext = encrypt_passphrase_for_assertion(b"locked", "pw");
    assert_eq!(
        decrypt_with_identities(&ciphertext, &[&identity]),
        Err(AgeswiftStatus::NoMatchingKey)
    );
}

// ------------------------------------------------------------ malformed input

#[test]
fn garbage_input_is_invalid_format() {
    let (identity, _) = generate();
    assert_eq!(
        decrypt_with_identities(b"not an age file at all", &[&identity]),
        Err(AgeswiftStatus::InvalidFormat)
    );
}

#[test]
fn truncated_and_corrupted_files_fail() {
    let (identity, recipient) = generate();
    let ciphertext = encrypt_for_assertion(b"some payload to corrupt", &[&recipient]);

    // Truncated header.
    let truncated = &ciphertext[..10];
    assert_eq!(
        decrypt_with_identities(truncated, &[&identity]),
        Err(AgeswiftStatus::InvalidFormat)
    );

    // Corrupt a byte of the payload (after the header and nonce) — this must
    // fail the ChaCha20Poly1305 authentication, not return bad plaintext.
    let mut corrupted = ciphertext.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xff;
    let result = decrypt_with_identities(&corrupted, &[&identity]);
    assert!(
        matches!(result, Err(AgeswiftStatus::DecryptionFailed)),
        "expected DecryptionFailed, got {result:?}"
    );

    // Corrupting the header stanza must also fail.
    let mut corrupted = ciphertext.clone();
    corrupted[30] ^= 0xff;
    let result = decrypt_with_identities(&corrupted, &[&identity]);
    assert!(result.is_err());
}

#[test]
fn invalid_utf8_identity_is_rejected() {
    let bad = b"\xff\xfe broken utf8";
    let mut error = ptr::null_mut();
    let status = ageswift_validate_identity(bad.as_ptr().cast(), &mut error);
    assert_status(AgeswiftStatus::InvalidArgument, status, error);
}

// ------------------------------------------------------------ pointer contracts

#[test]
fn empty_buffers_accept_null_pointers() {
    let (_, recipient) = generate();
    // NULL + zero length is a legal empty plaintext.
    assert_eq!(
        encrypt_to_recipients(&[], &[&recipient]),
        AgeswiftStatus::Ok
    );

    // NULL with nonzero length is an argument error.
    let mut ciphertext = zeroed_bytes();
    let mut error = ptr::null_mut();
    let c_recipient = CString::new(recipient).unwrap();
    let ptrs = [c_recipient.as_ptr()];
    let status = ageswift_encrypt_to_recipients(
        ptr::null(),
        5,
        ptrs.as_ptr(),
        1,
        &mut ciphertext,
        &mut error,
    );
    assert_status(AgeswiftStatus::InvalidArgument, status, error);

    // NULL output pointers are argument errors.
    let mut error = ptr::null_mut();
    let status = ageswift_encrypt_to_recipients(
        ptr::null(),
        0,
        ptrs.as_ptr(),
        1,
        ptr::null_mut(),
        &mut error,
    );
    assert_status(AgeswiftStatus::InvalidArgument, status, error);
}

#[test]
fn empty_recipient_and_identity_lists_are_rejected() {
    let mut error = ptr::null_mut();
    let mut ciphertext = zeroed_bytes();
    let status =
        ageswift_encrypt_to_recipients(ptr::null(), 0, ptr::null(), 0, &mut ciphertext, &mut error);
    assert_status(AgeswiftStatus::InvalidArgument, status, error);

    let mut plaintext = zeroed_bytes();
    let status = ageswift_decrypt_with_identities(
        ptr::null(),
        0,
        ptr::null(),
        0,
        &mut plaintext,
        &mut error,
    );
    assert_status(AgeswiftStatus::InvalidArgument, status, error);
}

#[test]
fn null_error_out_is_safe() {
    let (_, recipient) = generate();
    // Failing call with NULL error_out must still return the right status.
    let bad = CString::new("definitely not a recipient").unwrap();
    let ptrs = [bad.as_ptr()];
    let mut ciphertext = zeroed_bytes();
    let status = ageswift_encrypt_to_recipients(
        ptr::null(),
        0,
        ptrs.as_ptr(),
        1,
        &mut ciphertext,
        ptr::null_mut(),
    );
    assert_eq!(status, AgeswiftStatus::InvalidRecipient);

    // Successful call with NULL error_out must not write anything.
    let good = CString::new(recipient).unwrap();
    let ptrs = [good.as_ptr()];
    let status = ageswift_encrypt_to_recipients(
        ptr::null(),
        0,
        ptrs.as_ptr(),
        1,
        &mut ciphertext,
        ptr::null_mut(),
    );
    assert_eq!(status, AgeswiftStatus::Ok);
    take_bytes(ciphertext);
}

#[test]
fn free_functions_tolerate_empty_and_null() {
    // Zero-initialized struct (ptr == null) is a no-op.
    ageswift_free_bytes(zeroed_bytes());
    ageswift_free_string(ptr::null_mut());
}
