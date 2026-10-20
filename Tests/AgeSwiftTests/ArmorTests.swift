import Foundation
import Testing
@testable import AgeSwift

/// ASCII armor: armored encryption, text-input decryption, keyless conversion.
@Suite(.serialized)
struct ArmorTests {

    @Test func armoredRecipientRoundTrip() throws {
        let identity = try AgeIdentity.generate()
        let plaintext = Data("armored hello".utf8)

        let armored = try Age.encryptArmored(plaintext, recipients: [identity.recipient])
        #expect(armored.hasPrefix("-----BEGIN AGE ENCRYPTED FILE-----\n"))
        #expect(armored.contains("-----END AGE ENCRYPTED FILE-----"))

        // Decrypt via both entry points: bytes and pasted text.
        #expect(try Age.decrypt(Data(armored.utf8), identities: [identity]) == plaintext)
        #expect(try Age.decrypt(armored, identities: [identity]) == plaintext)
    }

    @Test func armoredPassphraseRoundTrip() throws {
        let plaintext = Data("armored passphrase secret".utf8)
        let armored = try Age.encryptArmored(plaintext, passphrase: "correct horse battery staple")

        #expect(armored.hasPrefix("-----BEGIN AGE ENCRYPTED FILE-----\n"))
        // Both entry points: pasted text and its UTF-8 bytes.
        #expect(try Age.decrypt(armored, passphrase: "correct horse battery staple") == plaintext)
        let asBytes = Data(armored.utf8)
        #expect(try Age.decrypt(asBytes, passphrase: "correct horse battery staple") == plaintext)
        #expect(throws: AgeError.noMatchingKey) {
            _ = try Age.decrypt(armored, passphrase: "wrong")
        }
    }

    @Test func pastedArmoredTextWithSurroundingWhitespace() throws {
        let identity = try AgeIdentity.generate()
        let plaintext = Data("paste me".utf8)
        let armored = try Age.encryptArmored(plaintext, recipients: [identity.recipient])

        // Text copied out of an email or chat carries stray whitespace.
        let pasted = "\r\n   \(armored)\n\t\n"
        #expect(try Age.decrypt(pasted, identities: [identity]) == plaintext)
        let dearmoredPasted = try Age.dearmor(pasted)
        let dearmoredClean = try Age.dearmor(armored)
        #expect(dearmoredPasted == dearmoredClean)
    }

    @Test func armoredEmptyAndBinaryPlaintext() throws {
        let identity = try AgeIdentity.generate()

        let empty = try Age.encryptArmored(Data(), recipients: [identity.recipient])
        #expect(try Age.decrypt(empty, identities: [identity]) == Data())

        var plaintext = Data(count: 100_000)
        for index in plaintext.indices { plaintext[index] = .random(in: .min ... .max) }
        let armored = try Age.encryptArmored(plaintext, recipients: [identity.recipient])
        // Base64 inflates by ~4/3; multi-line output is expected.
        #expect(armored.utf8.count > plaintext.count)
        #expect(try Age.decrypt(armored, identities: [identity]) == plaintext)
    }

    @Test func armorAndDearmorConversion() throws {
        let identity = try AgeIdentity.generate()
        let plaintext = Data("convert me".utf8)
        let binary = try Age.encrypt(plaintext, recipients: [identity.recipient])

        let armored = try Age.armor(binary)
        #expect(armored.hasPrefix("-----BEGIN AGE ENCRYPTED FILE-----\n"))
        // Byte-exact inverse, and both forms decrypt.
        #expect(try Age.dearmor(armored) == binary)
        #expect(try Age.decrypt(binary, identities: [identity]) == plaintext)
        #expect(try Age.decrypt(armored, identities: [identity]) == plaintext)
    }

    @Test func armorRejectsNonAgeInput() {
        AgeErrorExpectations.expectInvalidFormat {
            _ = try Age.armor(Data("not an age file".utf8))
        }
        AgeErrorExpectations.expectInvalidFormat {
            _ = try Age.armor(Data())
        }
    }

    @Test func dearmorIsStrict() throws {
        AgeErrorExpectations.expectInvalidFormat {
            _ = try Age.dearmor("plain text without markers")
        }
        AgeErrorExpectations.expectInvalidFormat {
            _ = try Age.dearmor("age-encryption.org/v1\n-> X25519 looks-binary")
        }
        // Truncated armor: END marker dropped.
        let identity = try AgeIdentity.generate()
        let binary = try Age.encrypt(Data("x".utf8), recipients: [identity.recipient])
        let armored = try Age.armor(binary)
        let truncated = armored
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.hasPrefix("-----END") }
            .joined(separator: "\n")
        AgeErrorExpectations.expectInvalidFormat {
            _ = try Age.dearmor(truncated)
        }
    }

    @Test func corruptedArmoredInputIsInvalidFormat() throws {
        let identity = try AgeIdentity.generate()
        let armored = try Age.encryptArmored(Data("payload".utf8), recipients: [identity.recipient])
        // Overwrite a base64 body character with one outside the alphabet.
        var corrupted = Array(armored.utf8)
        corrupted[60] = UInt8(ascii: "~")
        AgeErrorExpectations.expectInvalidFormat {
            _ = try Age.decrypt(Data(corrupted), identities: [identity])
        }
        AgeErrorExpectations.expectInvalidFormat {
            _ = try Age.dearmor(String(decoding: corrupted, as: UTF8.self))
        }
    }
}
