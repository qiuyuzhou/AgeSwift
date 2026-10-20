//! Error type for the core (non-FFI) layer.
//!
//! Messages are converted into C strings at the FFI boundary. They must
//! never contain key material, passphrases, or plaintext; every message is
//! either a static string or derived from `age` error values that do not
//! embed secrets.

use std::fmt;

#[derive(Debug)]
pub(crate) enum CoreError {
    InvalidArgument(&'static str),
    InvalidIdentity,
    InvalidRecipient,
    EncryptionFailed(String),
    DecryptionFailed(String),
    NoMatchingKey,
    /// The input is not a usable age file in either representation. The
    /// detail explains whether the binary structure or the ASCII armor is
    /// at fault; it never contains secrets.
    InvalidFormat(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(what) => write!(f, "{what}"),
            Self::InvalidIdentity => write!(f, "not a valid age secret identity string"),
            Self::InvalidRecipient => write!(f, "not a valid age recipient string"),
            Self::EncryptionFailed(detail) => write!(f, "encryption failed: {detail}"),
            Self::DecryptionFailed(detail) => write!(f, "decryption failed: {detail}"),
            Self::NoMatchingKey => {
                write!(f, "no provided identity or passphrase matches this file")
            }
            Self::InvalidFormat(detail) => write!(f, "input is not a valid age file: {detail}"),
        }
    }
}
