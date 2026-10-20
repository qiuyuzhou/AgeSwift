import Foundation
import AgeSwiftFFI

/// A public age recipient — an `age1...` Bech32 string.
///
/// A recipient contains only public key material, so unlike
/// ``AgeIdentity`` it is safe to store, print, and share.
public struct AgeRecipient: Sendable, Hashable, CustomStringConvertible {
    /// The Bech32 recipient string (`age1...`), exactly as provided.
    ///
    /// This is the string you pass to age-compatible CLIs (`age -r ...`).
    public let serialized: String

    /// Internal initializer for strings already validated by Rust
    /// (used when the recipient is derived inside the FFI).
    init(unchecked string: String) {
        self.serialized = string
    }

    /// Parses and validates an age recipient string.
    /// - Throws: ``AgeError/invalidRecipient`` if the string is malformed.
    public init(string: String) throws {
        var error: UnsafeMutablePointer<CChar>?
        try AgeFFI.withCString(string) { cString in
            let status = ageswift_validate_recipient(cString, &error)
            try AgeError.throwIfFailure(status, error)
        }
        self.serialized = string
    }

    /// The recipient string. Safe to display: recipients are public keys.
    public var description: String { serialized }
}
