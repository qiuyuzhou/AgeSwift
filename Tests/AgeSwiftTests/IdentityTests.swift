import Foundation
import Testing
@testable import AgeSwift

/// Identity generation, parsing, and secret-redaction guarantees.
@Suite
struct IdentityTests {

    @Test func generationProducesDistinctIdentities() throws {
        let a = try AgeIdentity.generate()
        let b = try AgeIdentity.generate()
        #expect(a != b)
        #expect(a.recipient != b.recipient)
        #expect(a.serialized.hasPrefix("AGE-SECRET-KEY-1"))
        #expect(a.recipient.serialized.hasPrefix("age1"))
    }

    @Test func generatedRecipientIsValid() throws {
        let identity = try AgeIdentity.generate()
        // Re-parsing the derived recipient must succeed.
        _ = try AgeRecipient(string: identity.recipient.serialized)
    }

    @Test func descriptionRedactsSecret() throws {
        let identity = try AgeIdentity.generate()
        #expect(!identity.description.contains(identity.serialized))
        #expect(!identity.debugDescription.contains(identity.serialized))
        // The recipient (public key) is intentionally visible.
        #expect(identity.description.contains(identity.recipient.serialized))
    }

    @Test func recipientDescriptionIsThePublicKey() throws {
        let recipient = try AgeRecipient(string: try AgeIdentity.generate().recipient.serialized)
        #expect(recipient.description == recipient.serialized)
    }

    @Test func explicitSerializationRoundTrips() throws {
        let identity = try AgeIdentity.generate()
        let restored = try AgeIdentity(string: identity.serialized)
        #expect(restored.serialized == identity.serialized)
        #expect(restored.recipient == identity.recipient)
    }
}
