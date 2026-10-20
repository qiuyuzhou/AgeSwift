import Foundation
import AgeSwiftFFI

/// A secret X25519 age identity — an `AGE-SECRET-KEY-1...` Bech32 string.
///
/// `AgeIdentity` is a value type wrapping the secret string. Anyone who
/// obtains ``serialized`` can decrypt files encrypted for ``recipient``,
/// so treat it like a password:
///
/// - Do not log it; `description` and `debugDescription` are redacted by
///   design. Serialization is deliberately explicit via ``serialized``.
/// - Do not persist it in plain text; storage (Keychain, file) is the
///   application's responsibility and out of scope for AgeSwift.
/// - Swift `String` storage cannot be zeroed; AgeSwift does not guarantee
///   erasure of copies created by Swift or Foundation. See README
///   "Security considerations".
public struct AgeIdentity: Sendable, Hashable {
    /// The secret Bech32 string, including the `AGE-SECRET-KEY-1` prefix.
    ///
    /// This is private key material. This is the string you keep in a
    /// key file for age-compatible CLIs (`age -d -i key.txt`).
    public let serialized: String

    /// The public recipient corresponding to this identity.
    public let recipient: AgeRecipient

    /// Generates a fresh identity using the operating system CSPRNG.
    public static func generate() throws -> AgeIdentity {
        var identityString: UnsafeMutablePointer<CChar>?
        var recipientString: UnsafeMutablePointer<CChar>?
        defer {
            AgeFFI.freeString(identityString)
            AgeFFI.freeString(recipientString)
        }
        var error: UnsafeMutablePointer<CChar>?
        let status = ageswift_generate_identity(&identityString, &recipientString, &error)
        try AgeError.throwIfFailure(status, error)
        guard let identityString, let recipientString else {
            throw AgeError.backendFailure("generate returned null output")
        }
        let secret = String(cString: identityString)
        let publicPart = String(cString: recipientString)
        return AgeIdentity(secretString: secret, recipientString: publicPart)
    }

    /// Internal initializer used by ``generate()`` where the recipient is
    /// already known, so it is not derived a second time.
    init(secretString: String, recipientString: String) {
        self.serialized = secretString
        self.recipient = AgeRecipient(unchecked: recipientString)
    }

    /// Parses a secret identity string (`AGE-SECRET-KEY-1...`) and derives
    /// its public recipient.
    /// - Throws: ``AgeError/invalidIdentity`` if the string is malformed.
    public init(string: String) throws {
        var recipientString: UnsafeMutablePointer<CChar>?
        defer { AgeFFI.freeString(recipientString) }
        var error: UnsafeMutablePointer<CChar>?
        try string.withCString { cString in
            let status = ageswift_identity_recipient(cString, &recipientString, &error)
            try AgeError.throwIfFailure(status, error)
        }
        guard let recipientString else {
            throw AgeError.backendFailure("identity_recipient returned null output")
        }
        self.init(secretString: string, recipientString: String(cString: recipientString))
    }
}

extension AgeIdentity: CustomStringConvertible, CustomDebugStringConvertible {
    /// Redacted by design; use ``serialized`` to access the secret explicitly.
    public var description: String {
        "<AgeIdentity: secret key (redacted); recipient: \(recipient.serialized)>"
    }

    /// Redacted by design; mirrors ``description``.
    public var debugDescription: String { description }
}
