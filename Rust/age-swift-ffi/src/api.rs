//! Core operations over the `age` crate, free of FFI concerns.
//!
//! Every function reports failures as [`CoreError`]; the FFI layer in
//! `ffi.rs` converts these into C status codes. Passphrases are held in
//! age's `SecretString`, which zeroizes its (Rust-side) buffer on drop.

use std::io::{Read, Write};
use std::str::FromStr;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::ExposeSecret;
use age::x25519;
use age::{Decryptor, Encryptor};

use crate::error::CoreError;

pub(crate) struct GeneratedIdentity {
    /// Bech32 `AGE-SECRET-KEY-1...` string (secret).
    pub(crate) identity: String,
    /// Bech32 `age1...` string (public).
    pub(crate) recipient: String,
}

pub(crate) fn generate_identity() -> GeneratedIdentity {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public();
    GeneratedIdentity {
        identity: identity.to_string().expose_secret().to_owned(),
        recipient: recipient.to_string(),
    }
}

pub(crate) fn parse_identity(s: &str) -> Result<x25519::Identity, CoreError> {
    // Deliberately discard the underlying error: it may quote the input.
    x25519::Identity::from_str(s).map_err(|_| CoreError::InvalidIdentity)
}

pub(crate) fn parse_recipient(s: &str) -> Result<x25519::Recipient, CoreError> {
    x25519::Recipient::from_str(s).map_err(|_| CoreError::InvalidRecipient)
}

pub(crate) fn identity_recipient(identity: &x25519::Identity) -> String {
    identity.to_public().to_string()
}

pub(crate) fn encrypt_to_recipients(
    plaintext: &[u8],
    recipients: &[x25519::Recipient],
    format: Format,
) -> Result<Vec<u8>, CoreError> {
    // An empty list is rejected at the FFI boundary (`input_str_list`).
    let recipients: Vec<&dyn age::Recipient> = recipients.iter().map(|r| r as _).collect();
    encrypt_impl(plaintext, recipients, format)
}

pub(crate) fn encrypt_with_passphrase(
    plaintext: &[u8],
    passphrase: &str,
    format: Format,
) -> Result<Vec<u8>, CoreError> {
    // Uses age's standard scrypt recipient with its default (~1 second)
    // benchmarked work factor; AgeSwift never selects custom KDF parameters.
    let recipient = age::scrypt::Recipient::new(passphrase.into());
    encrypt_impl(plaintext, vec![&recipient], format)
}

fn encrypt_impl(
    plaintext: &[u8],
    recipients: Vec<&dyn age::Recipient>,
    format: Format,
) -> Result<Vec<u8>, CoreError> {
    let encryptor = Encryptor::with_recipients(recipients.into_iter())
        .map_err(|e| CoreError::EncryptionFailed(e.to_string()))?;
    let mut ciphertext = Vec::new();
    // `ArmoredWriter` with `Format::Binary` is a transparent passthrough, so
    // both formats share one path; armored output requires finishing both
    // writers (the age writer flushes into the armor writer, which then
    // writes the END marker).
    let armor = ArmoredWriter::wrap_output(&mut ciphertext, format)
        .map_err(|e| CoreError::EncryptionFailed(e.to_string()))?;
    let mut writer = encryptor
        .wrap_output(armor)
        .map_err(|e| CoreError::EncryptionFailed(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| CoreError::EncryptionFailed(e.to_string()))?;
    writer
        .finish()
        .and_then(|armor| armor.finish())
        .map_err(|e| CoreError::EncryptionFailed(e.to_string()))?;
    Ok(ciphertext)
}

pub(crate) fn decrypt_with_identities(
    ciphertext: &[u8],
    identities: &[x25519::Identity],
) -> Result<Vec<u8>, CoreError> {
    // An empty list is rejected at the FFI boundary (`input_str_list`).
    let identities: Vec<&dyn age::Identity> = identities.iter().map(|i| i as _).collect();
    decrypt_impl(ciphertext, identities)
}

pub(crate) fn decrypt_with_passphrase(
    ciphertext: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>, CoreError> {
    // age caps the accepted scrypt work factor at its benchmarked target
    // plus four levels, matching upstream CLI behavior.
    let identity = age::scrypt::Identity::new(passphrase.into());
    decrypt_impl(ciphertext, vec![&identity])
}

fn decrypt_impl(
    ciphertext: &[u8],
    identities: Vec<&dyn age::Identity>,
) -> Result<Vec<u8>, CoreError> {
    // `ArmoredReader` transparently detects the age ASCII armor format and
    // passes binary files through unchanged, matching the age CLI: decrypt
    // accepts either representation. Whitespace preceding an armored block
    // is stripped first (see `strip_leading_armor_whitespace`).
    let ciphertext =
        strip_leading_armor_whitespace(ciphertext).unwrap_or(ciphertext);
    let decryptor =
        Decryptor::new(ArmoredReader::new(ciphertext)).map_err(map_decrypt_error)?;
    let mut reader = decryptor
        .decrypt(identities.into_iter())
        .map_err(map_decrypt_error)?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(map_read_error)?;
    Ok(plaintext)
}

const ARMORED_BEGIN_MARKER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

/// Positions armored input at its begin marker.
///
/// The age format (and the Go reference CLI) allow whitespace before the
/// armored block, but the Rust `ArmoredReader` only detects armor that
/// starts at byte zero. To keep paste-friendly inputs working, leading
/// ASCII whitespace is stripped here before the reader sees the data.
/// Returns `None` when the input does not begin with the marker after any
/// whitespace prefix, leaving non-armored (binary) input untouched.
fn strip_leading_armor_whitespace(input: &[u8]) -> Option<&[u8]> {
    if input.starts_with(ARMORED_BEGIN_MARKER.as_bytes()) {
        return Some(input);
    }
    let is_whitespace = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0b' | b'\x0c');
    let marker_start = input.iter().position(|b| !is_whitespace(*b))?;
    input[marker_start..]
        .starts_with(ARMORED_BEGIN_MARKER.as_bytes())
        .then(|| &input[marker_start..])
}

/// Structural validation shared by the conversion functions: parses the age
/// header, including the MAC field. The MAC value itself is only checked when
/// a key opens the file, so this verifies structure, not integrity. No keys
/// are involved.
fn validate_age_file(binary: &[u8]) -> Result<(), CoreError> {
    Decryptor::new(binary).map_err(map_decrypt_error).map(|_| ())
}

/// Wraps a structurally valid binary age file in the ASCII armor format.
pub(crate) fn armor(binary: &[u8]) -> Result<String, CoreError> {
    validate_age_file(binary)?;
    let mut armored = Vec::new();
    let mut writer = ArmoredWriter::wrap_output(&mut armored, Format::AsciiArmor)
        .map_err(|e| CoreError::InvalidFormat(e.to_string()))?;
    writer
        .write_all(binary)
        .and_then(|_| writer.finish())
        .map_err(|e| CoreError::InvalidFormat(e.to_string()))?;
    String::from_utf8(armored).map_err(|_| {
        // Unreachable in practice: armor output is ASCII by construction.
        CoreError::InvalidFormat("armor writer produced non-UTF-8 output".to_owned())
    })
}

/// Decodes an age ASCII armor file back to the binary format. Strictly
/// requires armored input: `ArmoredReader` would silently pass binary input
/// through, so the marker is checked explicitly first.
pub(crate) fn dearmor(armored: &str) -> Result<Vec<u8>, CoreError> {
    let input = strip_leading_armor_whitespace(armored.as_bytes()).ok_or_else(|| {
        CoreError::InvalidFormat("input does not start with the age armor header".to_owned())
    })?;
    let mut reader = ArmoredReader::new(input);
    let mut binary = Vec::new();
    reader
        .read_to_end(&mut binary)
        .map_err(|e| CoreError::InvalidFormat(format!("invalid ASCII armor: {e}")))?;
    validate_age_file(&binary)?;
    Ok(binary)
}

/// True when the error is an armor-structure failure wrapped by the `age`
/// crate's reader in an `io::Error`.
fn is_armor_read_error(e: &std::io::Error) -> bool {
    e.get_ref()
        .and_then(|source| source.downcast_ref::<age::armor::ArmoredReadError>())
        .is_some()
}

/// Maps read errors from the decryption stream. Armor-structure failures
/// mean the input was not a valid armored file; anything else is payload
/// corruption.
fn map_read_error(e: std::io::Error) -> CoreError {
    if is_armor_read_error(&e) {
        CoreError::InvalidFormat(format!("invalid ASCII armor: {e}"))
    } else {
        CoreError::DecryptionFailed(e.to_string())
    }
}

fn map_decrypt_error(e: age::DecryptError) -> CoreError {
    use age::DecryptError;
    use std::io::ErrorKind;
    let detail = e.to_string();
    match e {
        DecryptError::UnknownFormat | DecryptError::InvalidHeader => {
            CoreError::InvalidFormat(detail)
        }
        // `DecryptionFailed` is produced when a stanza matched the identity
        // type but the wrapped file key failed to open (wrong passphrase for
        // scrypt); `NoMatchingKeys` when no stanza matched any identity;
        // `KeyDecryptionFailed` when a matched stanza could not be unwrapped.
        // All three mean "wrong key or passphrase" to the caller.
        DecryptError::DecryptionFailed
        | DecryptError::NoMatchingKeys
        | DecryptError::KeyDecryptionFailed => CoreError::NoMatchingKey,
        // Armor-structure failures during header parsing are format errors;
        // checked before the EOF arm so truncated armor still gets the
        // specific "invalid ASCII armor" detail.
        DecryptError::Io(ref inner) if is_armor_read_error(inner) => {
            CoreError::InvalidFormat(format!("invalid ASCII armor: {inner}"))
        }
        // A file cut off inside its header is not a valid age file.
        DecryptError::Io(inner) if inner.kind() == ErrorKind::UnexpectedEof => {
            CoreError::InvalidFormat(detail)
        }
        // Header MAC mismatch, excessive scrypt work factor, and any other
        // structural failure: the bytes are not a trustworthy age file.
        // The age error text does not embed secrets.
        other => CoreError::DecryptionFailed(other.to_string()),
    }
}
