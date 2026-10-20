import Foundation
import AgeSwiftFFI

/// Namespace for in-memory age v1 encryption and decryption.
///
/// All functions are stateless, thread-safe, and blocking: scrypt passphrase
/// operations cost about one second of CPU each (age's standard work factor),
/// and decrypting a hostile file can cost up to ~16x that (see README
/// "Security considerations"), so call them off the main thread if that
/// matters to your application.
public enum Age {

    // MARK: - Encryption

    /// Encrypts `plaintext` for one or more recipients into a binary age v1 file.
    ///
    /// Any provided identity (or any age-compatible CLI holding a matching
    /// key file) can decrypt the result.
    /// - Throws: ``AgeError/invalidRecipient`` if a recipient string is
    ///   malformed; ``AgeError/encryptionFailed`` on backend failure.
    public static func encrypt(_ plaintext: Data, recipients: [AgeRecipient]) throws -> Data {
        try encryptImpl(plaintext, recipients: recipients, format: AGESWIFT_FORMAT_BINARY)
    }

    /// Encrypts `plaintext` for one or more recipients into an age ASCII
    /// armor file (PEM-like text, safe to paste into emails and chats).
    ///
    /// The result decrypts with any age implementation, including
    /// ``decrypt(_:identities:)`` — both representations are accepted.
    /// - Throws: ``AgeError/invalidRecipient`` if a recipient string is
    ///   malformed; ``AgeError/encryptionFailed`` on backend failure.
    public static func encryptArmored(_ plaintext: Data, recipients: [AgeRecipient]) throws -> String {
        try AgeFFI.textFromBytes(
            try encryptImpl(plaintext, recipients: recipients, format: AGESWIFT_FORMAT_ASCII_ARMOR)
        )
    }

    /// Encrypts `plaintext` with a passphrase using age's standard scrypt
    /// recipient and its default (~1 second) work factor.
    /// - Throws: ``AgeError/encryptionFailed`` on backend failure.
    public static func encrypt(_ plaintext: Data, passphrase: String) throws -> Data {
        try encryptImpl(plaintext, passphrase: passphrase, format: AGESWIFT_FORMAT_BINARY)
    }

    /// Encrypts `plaintext` with a passphrase into an age ASCII armor file.
    ///
    /// The result decrypts with any age implementation, including
    /// ``decrypt(_:passphrase:)`` — both representations are accepted.
    /// - Throws: ``AgeError/encryptionFailed`` on backend failure.
    public static func encryptArmored(_ plaintext: Data, passphrase: String) throws -> String {
        try AgeFFI.textFromBytes(
            try encryptImpl(plaintext, passphrase: passphrase, format: AGESWIFT_FORMAT_ASCII_ARMOR)
        )
    }

    private static func encryptImpl(
        _ plaintext: Data,
        recipients: [AgeRecipient],
        format: ageswift_format
    ) throws -> Data {
        let strings = recipients.map(\.serialized)
        return try AgeFFI.withBytes(of: plaintext) { bytes, count in
            try AgeFFI.withCStringsAsArray(strings) { recipientArray in
                try recipientArray.withUnsafeBufferPointer { buffer in
                    var output = ageswift_bytes()
                    var error: UnsafeMutablePointer<CChar>?
                    let status = ageswift_encrypt_to_recipients(
                        bytes, UInt(count),
                        buffer.baseAddress, UInt(buffer.count),
                        format,
                        &output, &error
                    )
                    try AgeError.throwIfFailure(status, error)
                    return try AgeFFI.copyAndFree(output)
                }
            }
        }
    }

    private static func encryptImpl(
        _ plaintext: Data,
        passphrase: String,
        format: ageswift_format
    ) throws -> Data {
        try AgeFFI.withBytes(of: plaintext) { bytes, count in
            try AgeFFI.withCString(passphrase) { passphraseCString in
                var output = ageswift_bytes()
                var error: UnsafeMutablePointer<CChar>?
                let status = ageswift_encrypt_with_passphrase(
                    bytes, UInt(count),
                    passphraseCString,
                    format,
                    &output, &error
                )
                try AgeError.throwIfFailure(status, error)
                return try AgeFFI.copyAndFree(output)
            }
        }
    }

    // MARK: - Decryption

    /// Decrypts an age file with one or more secret identities.
    ///
    /// Both representations are accepted: binary age v1 files and ASCII
    /// armor (leading and trailing whitespace around an armored block is
    /// ignored, so pasted text works).
    /// - Throws: ``AgeError/invalidFormat`` if the input is not an age file;
    ///   ``AgeError/noMatchingKey`` if none of the identities matches;
    ///   ``AgeError/decryptionFailed`` if the payload is corrupted or
    ///   truncated.
    public static func decrypt(_ ciphertext: Data, identities: [AgeIdentity]) throws -> Data {
        let strings = identities.map(\.serialized)
        return try AgeFFI.withBytes(of: ciphertext) { bytes, count in
            try AgeFFI.withCStringsAsArray(strings) { identityArray in
                try identityArray.withUnsafeBufferPointer { buffer in
                    var output = ageswift_bytes()
                    var error: UnsafeMutablePointer<CChar>?
                    let status = ageswift_decrypt_with_identities(
                        bytes, UInt(count),
                        buffer.baseAddress, UInt(buffer.count),
                        &output, &error
                    )
                    try AgeError.throwIfFailure(status, error)
                    return try AgeFFI.copyAndFree(output)
                }
            }
        }
    }

    /// Decrypts an age file with one or more secret identities, accepting
    /// ciphertext as text (typically pasted ASCII armor; binary data passed
    /// as UTF-8 text also works).
    ///
    /// - Throws: ``AgeError/invalidFormat`` if the input is not an age file;
    ///   ``AgeError/noMatchingKey`` if none of the identities matches;
    ///   ``AgeError/decryptionFailed`` if the payload is corrupted or
    ///   truncated.
    public static func decrypt(_ ciphertext: String, identities: [AgeIdentity]) throws -> Data {
        try decrypt(Data(ciphertext.utf8), identities: identities)
    }

    /// Decrypts a passphrase-protected (scrypt) age file.
    ///
    /// Both representations are accepted: binary age v1 files and ASCII
    /// armor (leading and trailing whitespace around an armored block is
    /// ignored, so pasted text works).
    /// - Throws: ``AgeError/invalidFormat`` if the input is not an age file;
    ///   ``AgeError/noMatchingKey`` on a wrong passphrase;
    ///   ``AgeError/decryptionFailed`` if the payload is corrupted or
    ///   truncated.
    public static func decrypt(_ ciphertext: Data, passphrase: String) throws -> Data {
        try AgeFFI.withBytes(of: ciphertext) { bytes, count in
            try AgeFFI.withCString(passphrase) { passphraseCString in
                var output = ageswift_bytes()
                var error: UnsafeMutablePointer<CChar>?
                let status = ageswift_decrypt_with_passphrase(
                    bytes, UInt(count),
                    passphraseCString,
                    &output, &error
                )
                try AgeError.throwIfFailure(status, error)
                return try AgeFFI.copyAndFree(output)
            }
        }
    }

    /// Decrypts a passphrase-protected (scrypt) age file, accepting
    /// ciphertext as text (typically pasted ASCII armor).
    ///
    /// - Throws: ``AgeError/invalidFormat`` if the input is not an age file;
    ///   ``AgeError/noMatchingKey`` on a wrong passphrase;
    ///   ``AgeError/decryptionFailed`` if the payload is corrupted or
    ///   truncated.
    public static func decrypt(_ ciphertext: String, passphrase: String) throws -> Data {
        try decrypt(Data(ciphertext.utf8), passphrase: passphrase)
    }
}
