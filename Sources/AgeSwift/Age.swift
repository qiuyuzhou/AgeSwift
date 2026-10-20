import Foundation
import AgeSwiftFFI

/// Namespace for in-memory age v1 encryption and decryption.
///
/// All functions are stateless, non-blocking-thread-safe, and blocking:
/// scrypt passphrase operations deliberately cost roughly one second of
/// CPU time (age's standard work factor), so call them off the main thread
/// if that matters to your application.
public enum Age {

    // MARK: - Encryption

    /// Encrypts `plaintext` for one or more recipients into a binary age v1 file.
    ///
    /// Any provided identity (or any age-compatible CLI holding a matching
    /// key file) can decrypt the result.
    /// - Throws: ``AgeError/invalidRecipient`` if a recipient string is
    ///   malformed; ``AgeError/encryptionFailed`` on backend failure.
    @discardableResult
    public static func encrypt(_ plaintext: Data, recipients: [AgeRecipient]) throws -> Data {
        guard !recipients.isEmpty else {
            throw AgeError.invalidArgument("at least one recipient is required")
        }
        let strings = recipients.map(\.serialized)
        return try AgeFFI.withBytes(of: plaintext) { bytes, count in
            try AgeFFI.withCStringsAsArray(strings) { recipientArray in
                try recipientArray.withUnsafeBufferPointer { buffer in
                    var output = ageswift_bytes()
                    var error: UnsafeMutablePointer<CChar>?
                    let status = ageswift_encrypt_to_recipients(
                        bytes, UInt(count),
                        buffer.baseAddress, UInt(buffer.count),
                        &output, &error
                    )
                    defer { AgeFFI.freeString(error) }
                    try AgeError.throwIfFailure(status, error)
                    return try AgeFFI.copyAndFree(output)
                }
            }
        }
    }

    /// Encrypts `plaintext` with a passphrase using age's standard scrypt
    /// recipient and its default (~1 second) work factor.
    /// - Throws: ``AgeError/encryptionFailed`` on backend failure.
    @discardableResult
    public static func encrypt(_ plaintext: Data, passphrase: String) throws -> Data {
        try AgeFFI.withBytes(of: plaintext) { bytes, count in
            try passphrase.withCString { passphraseCString in
                var output = ageswift_bytes()
                var error: UnsafeMutablePointer<CChar>?
                let status = ageswift_encrypt_with_passphrase(
                    bytes, UInt(count),
                    passphraseCString,
                    &output, &error
                )
                defer { AgeFFI.freeString(error) }
                try AgeError.throwIfFailure(status, error)
                return try AgeFFI.copyAndFree(output)
            }
        }
    }

    // MARK: - Decryption

    /// Decrypts a binary age v1 file with one or more secret identities.
    ///
    /// - Throws: ``AgeError/invalidFormat`` if the input is not an age file;
    ///   ``AgeError/noMatchingKey`` if none of the identities matches;
    ///   ``AgeError/decryptionFailed`` if the payload is corrupted or
    ///   truncated.
    @discardableResult
    public static func decrypt(_ ciphertext: Data, identities: [AgeIdentity]) throws -> Data {
        guard !identities.isEmpty else {
            throw AgeError.invalidArgument("at least one identity is required")
        }
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
                    defer { AgeFFI.freeString(error) }
                    try AgeError.throwIfFailure(status, error)
                    return try AgeFFI.copyAndFree(output)
                }
            }
        }
    }

    /// Decrypts a passphrase-protected (scrypt) age file.
    ///
    /// - Throws: ``AgeError/invalidFormat`` if the input is not an age file;
    ///   ``AgeError/noMatchingKey`` on a wrong passphrase;
    ///   ``AgeError/decryptionFailed`` if the payload is corrupted or
    ///   truncated.
    @discardableResult
    public static func decrypt(_ ciphertext: Data, passphrase: String) throws -> Data {
        try AgeFFI.withBytes(of: ciphertext) { bytes, count in
            try passphrase.withCString { passphraseCString in
                var output = ageswift_bytes()
                var error: UnsafeMutablePointer<CChar>?
                let status = ageswift_decrypt_with_passphrase(
                    bytes, UInt(count),
                    passphraseCString,
                    &output, &error
                )
                defer { AgeFFI.freeString(error) }
                try AgeError.throwIfFailure(status, error)
                return try AgeFFI.copyAndFree(output)
            }
        }
    }
}
