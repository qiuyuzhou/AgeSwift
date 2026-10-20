import Foundation
import Testing
@testable import AgeSwift

/// Assertions shared across test suites.
enum AgeErrorExpectations {

    /// Asserts that `body` throws `.invalidFormat` regardless of the
    /// backend-supplied detail message.
    static func expectInvalidFormat(_ body: () throws -> Void) {
        do {
            try body()
            Issue.record("expected an invalidFormat error")
        } catch let error as AgeError {
            guard case .invalidFormat = error else {
                Issue.record("expected invalidFormat, got \(error)")
                return
            }
        } catch {
            Issue.record("expected AgeError.invalidFormat, got \(error)")
        }
    }
}
