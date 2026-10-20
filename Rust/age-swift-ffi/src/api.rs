//! Core operations over the `age` crate, free of FFI concerns.
//!
//! Every function reports failures as [`CoreError`]; the FFI layer in
//! `ffi.rs` converts these into C status codes. Passphrases are held in
//! age's `SecretString`, which zeroizes its (Rust-side) buffer on drop.

use std::io::{Read, Write};
use std::str::FromStr;

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
) -> Result<Vec<u8>, CoreError> {
    if recipients.is_empty() {
        return Err(CoreError::InvalidArgument(
            "at least one recipient is required",
        ));
    }
    let recipients: Vec<&dyn age::Recipient> = recipients.iter().map(|r| r as _).collect();
    encrypt_impl(plaintext, recipients)
}

pub(crate) fn encrypt_with_passphrase(
    plaintext: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>, CoreError> {
    // Uses age's standard scrypt recipient with its default (~1 second)
    // benchmarked work factor; AgeSwift never selects custom KDF parameters.
    let recipient = age::scrypt::Recipient::new(passphrase.into());
    encrypt_impl(plaintext, vec![&recipient])
}

fn encrypt_impl(
    plaintext: &[u8],
    recipients: Vec<&dyn age::Recipient>,
) -> Result<Vec<u8>, CoreError> {
    let encryptor = Encryptor::with_recipients(recipients.into_iter())
        .map_err(|e| CoreError::EncryptionFailed(e.to_string()))?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| CoreError::EncryptionFailed(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| CoreError::EncryptionFailed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| CoreError::EncryptionFailed(e.to_string()))?;
    Ok(ciphertext)
}

pub(crate) fn decrypt_with_identities(
    ciphertext: &[u8],
    identities: &[x25519::Identity],
) -> Result<Vec<u8>, CoreError> {
    if identities.is_empty() {
        return Err(CoreError::InvalidArgument(
            "at least one identity is required",
        ));
    }
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
    let decryptor = Decryptor::new(ciphertext).map_err(map_decrypt_error)?;
    let mut reader = decryptor
        .decrypt(identities.into_iter())
        .map_err(map_decrypt_error)?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| CoreError::DecryptionFailed(e.to_string()))?;
    Ok(plaintext)
}

fn map_decrypt_error(e: age::DecryptError) -> CoreError {
    use age::DecryptError;
    use std::io::ErrorKind;
    match e {
        DecryptError::UnknownFormat | DecryptError::InvalidHeader => CoreError::InvalidFormat,
        // `DecryptionFailed` is produced when a stanza matched the identity
        // type but the wrapped file key failed to open (wrong passphrase for
        // scrypt); `NoMatchingKeys` when no stanza matched any identity;
        // `KeyDecryptionFailed` when a matched stanza could not be unwrapped.
        // All three mean "wrong key or passphrase" to the caller.
        DecryptError::DecryptionFailed
        | DecryptError::NoMatchingKeys
        | DecryptError::KeyDecryptionFailed => CoreError::NoMatchingKey,
        // A file cut off inside its header is not a valid age file.
        DecryptError::Io(inner) if inner.kind() == ErrorKind::UnexpectedEof => {
            CoreError::InvalidFormat
        }
        // Header MAC mismatch, excessive scrypt work factor, and any other
        // structural failure: the bytes are not a trustworthy age file.
        // The age error text does not embed secrets.
        other => CoreError::DecryptionFailed(other.to_string()),
    }
}
