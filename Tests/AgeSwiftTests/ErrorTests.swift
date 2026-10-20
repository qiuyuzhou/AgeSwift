import Foundation
import Testing
@testable import AgeSwift

/// Error taxonomy and propagation from the Rust backend.
@Suite(.serialized)
struct ErrorTests {

    @Test func invalidRecipientString() {
        #expect(throws: AgeError.invalidRecipient) {
            _ = try AgeRecipient(string: "not-a-recipient")
        }
        #expect(throws: AgeError.invalidRecipient) {
            // An identity string is not a recipient.
            _ = try AgeRecipient(string: try AgeIdentity.generate().serialized)
        }
    }

    @Test func invalidIdentityString() {
        #expect(throws: AgeError.invalidIdentity) {
            _ = try AgeIdentity(string: "AGE-SECRET-KEY-1GIBBERISH")
        }
        #expect(throws: AgeError.invalidIdentity) {
            // A recipient string is not an identity.
            _ = try AgeIdentity(string: "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
        }
    }

    @Test func emptyCollectionsRejected() throws {
        let identity = try AgeIdentity.generate()
        let encrypted = try Age.encrypt(Data("x".utf8), recipients: [identity.recipient])

        #expect(throws: AgeError.invalidArgument("at least one recipient is required")) {
            _ = try Age.encrypt(Data(), recipients: [])
        }
        #expect(throws: AgeError.self) {
            _ = try Age.decrypt(encrypted, identities: [])
        }
    }

    @Test func wrongIdentityIsNoMatchingKey() throws {
        let encryptor = try AgeIdentity.generate()
        let other = try AgeIdentity.generate()
        let encrypted = try Age.encrypt(Data("secret".utf8), recipients: [encryptor.recipient])
        #expect(throws: AgeError.noMatchingKey) {
            _ = try Age.decrypt(encrypted, identities: [other])
        }
    }

    @Test func wrongPassphraseIsNoMatchingKey() throws {
        let encrypted = try Age.encrypt(Data("secret".utf8), passphrase: "right")
        #expect(throws: AgeError.noMatchingKey) {
            _ = try Age.decrypt(encrypted, passphrase: "wrong")
        }
    }

    @Test func crossModeDecryptionFails() throws {
        let identity = try AgeIdentity.generate()
        let passphraseEncrypted = try Age.encrypt(Data("locked".utf8), passphrase: "pw")
        #expect(throws: AgeError.noMatchingKey) {
            _ = try Age.decrypt(passphraseEncrypted, identities: [identity])
        }

        let keyEncrypted = try Age.encrypt(Data("locked".utf8), recipients: [identity.recipient])
        #expect(throws: AgeError.noMatchingKey) {
            _ = try Age.decrypt(keyEncrypted, passphrase: "pw")
        }
    }

    @Test func garbageInputIsInvalidFormat() throws {
        let identity = try AgeIdentity.generate()
        #expect(throws: AgeError.invalidFormat) {
            _ = try Age.decrypt(Data("definitely not an age file".utf8), identities: [identity])
        }
        #expect(throws: AgeError.invalidFormat) {
            _ = try Age.decrypt(Data(), identities: [identity])
        }
        #expect(throws: AgeError.invalidFormat) {
            // Truncated right after the magic line.
            _ = try Age.decrypt(Data("age-encryption.org/v1\n".utf8), identities: [identity])
        }
    }

    @Test func corruptedPayloadIsDecryptionFailed() throws {
        let identity = try AgeIdentity.generate()
        var encrypted = try Age.encrypt(Data("some payload".utf8), recipients: [identity.recipient])
        encrypted[encrypted.count - 1] ^= 0xFF
        #expect(throws: Error.self) {
            _ = try Age.decrypt(encrypted, identities: [identity])
        }
        // Non-exhaustive enum check for the exact case:
        do {
            _ = try Age.decrypt(encrypted, identities: [identity])
            Issue.record("expected decryption to fail")
        } catch let error as AgeError {
            guard case .decryptionFailed = error else {
                Issue.record("expected decryptionFailed, got \(error)")
                return
            }
        }
    }

    @Test func errorDescriptionsNeverContainSecrets() throws {
        let identity = try AgeIdentity.generate()
        let passphrase = "super-secret-passphrase-1234"

        let cases: [AgeError] = [
            .invalidRecipient,
            .invalidIdentity,
            .noMatchingKey,
            .invalidFormat,
        ]
        for error in cases {
            #expect(!error.description.contains(passphrase))
            #expect(!error.description.contains(identity.serialized))
        }

        // Live errors from the backend must also be secret-free.
        let encrypted = try Age.encrypt(Data("secret".utf8), passphrase: passphrase)
        do {
            _ = try Age.decrypt(encrypted, passphrase: "wrong")
            Issue.record("expected failure")
        } catch let error as AgeError {
            #expect(!error.description.contains(passphrase))
        }
    }

    @Test func bufferOwnershipAcrossManyCalls() throws {
        // Repeated calls through the FFI exercise allocation/copy/free paths;
        // leaks or double-frees would destabilize the suite (and show up
        // under Address Sanitizer or Malloc Stack logging).
        let identity = try AgeIdentity.generate()
        for _ in 0..<20 {
            let encrypted = try Age.encrypt(Data("ownership".utf8), recipients: [identity.recipient])
            _ = try Age.decrypt(encrypted, identities: [identity])
        }
    }
}
