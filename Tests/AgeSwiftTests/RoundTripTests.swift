import Foundation
import Testing
@testable import AgeSwift

/// Core round-trip coverage: X25519, scrypt, edge-case payloads.
@Suite(.serialized)
struct RoundTripTests {

    @Test func x25519RoundTrip() throws {
        let identity = try AgeIdentity.generate()
        let plaintext = Data("Hello AgeSwift".utf8)
        let encrypted = try Age.encrypt(plaintext, recipients: [identity.recipient])
        #expect(encrypted.starts(with: Data("age-encryption.org/v1\n".utf8)))
        #expect(!encrypted.elementsEqual(plaintext))
        let decrypted = try Age.decrypt(encrypted, identities: [identity])
        #expect(decrypted == plaintext)
    }

    @Test func passphraseRoundTrip() throws {
        let plaintext = Data("passphrase protected".utf8)
        let encrypted = try Age.encrypt(plaintext, passphrase: "a secret passphrase")
        let decrypted = try Age.decrypt(encrypted, passphrase: "a secret passphrase")
        #expect(decrypted == plaintext)
    }

    @Test func emptyPlaintextBothModes() throws {
        let identity = try AgeIdentity.generate()
        let encrypted = try Age.encrypt(Data(), recipients: [identity.recipient])
        #expect(try Age.decrypt(encrypted, identities: [identity]) == Data())

        let passphraseEncrypted = try Age.encrypt(Data(), passphrase: "pw")
        #expect(try Age.decrypt(passphraseEncrypted, passphrase: "pw") == Data())
    }

    @Test func unicodePlaintext() throws {
        let identity = try AgeIdentity.generate()
        let plaintext = Data("你好,age! 🕊️ naïve café — ¿ UTF-8 round trip?".utf8)
        let encrypted = try Age.encrypt(plaintext, recipients: [identity.recipient])
        #expect(try Age.decrypt(encrypted, identities: [identity]) == plaintext)
    }

    @Test func binaryPlaintextWithNullBytes() throws {
        let identity = try AgeIdentity.generate()
        var plaintext = Data()
        for _ in 0..<1000 { plaintext.append(UInt8.random(in: .min ... .max)) }
        plaintext.replaceSubrange(10..<60, with: Data(repeating: 0, count: 50))

        let encrypted = try Age.encrypt(plaintext, recipients: [identity.recipient])
        #expect(try Age.decrypt(encrypted, identities: [identity]) == plaintext)
    }

    @Test func largePlaintext() throws {
        // 5 MB exercises the STREAM payload chunking in both directions.
        let identity = try AgeIdentity.generate()
        var plaintext = Data(count: 5 * 1024 * 1024)
        for index in plaintext.indices { plaintext[index] = UInt8.random(in: .min ... .max) }

        let encrypted = try Age.encrypt(plaintext, recipients: [identity.recipient])
        #expect(try Age.decrypt(encrypted, identities: [identity]) == plaintext)
    }

    @Test func multipleRecipientsEachIdentityDecrypts() throws {
        let alice = try AgeIdentity.generate()
        let bob = try AgeIdentity.generate()
        let mallory = try AgeIdentity.generate()
        let plaintext = Data("for alice and bob".utf8)

        let encrypted = try Age.encrypt(plaintext, recipients: [alice.recipient, bob.recipient])
        #expect(try Age.decrypt(encrypted, identities: [alice]) == plaintext)
        #expect(try Age.decrypt(encrypted, identities: [bob]) == plaintext)
        #expect(try Age.decrypt(encrypted, identities: [mallory, bob]) == plaintext)
        #expect(throws: AgeError.noMatchingKey) {
            try Age.decrypt(encrypted, identities: [mallory])
        }
    }

    @Test func repeatedEncryptDecryptIsStable() throws {
        let identity = try AgeIdentity.generate()
        let plaintext = Data("repeat me".utf8)

        var previous: Data?
        for _ in 0..<5 {
            let encrypted = try Age.encrypt(plaintext, recipients: [identity.recipient])
            #expect(try Age.decrypt(encrypted, identities: [identity]) == plaintext)
            // Fresh randomness per file: ciphertexts must differ every time.
            if let previous { #expect(encrypted != previous) }
            previous = encrypted
        }
    }

    @Test func parsedIdentityBehavesLikeGenerated() throws {
        let original = try AgeIdentity.generate()
        let restored = try AgeIdentity(string: original.serialized)
        #expect(restored == original)
        #expect(restored.recipient == original.recipient)

        let plaintext = Data("parsed identity".utf8)
        let encrypted = try Age.encrypt(plaintext, recipients: [restored.recipient])
        #expect(try Age.decrypt(encrypted, identities: [original]) == plaintext)
    }
}
