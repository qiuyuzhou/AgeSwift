import Foundation
import AgeSwiftFFI

extension Age {

    // MARK: - Armor conversion

    /// Wraps a binary age file in the age ASCII armor format.
    ///
    /// The input is structurally validated first (header parse — no keys are
    /// involved), so anything that is not an age file throws
    /// ``AgeError/invalidFormat``. No keys, passphrases, or plaintext are
    /// required: converting between the two representations never decrypts.
    /// - Throws: ``AgeError/invalidFormat`` if `binary` is not an age file.
    @discardableResult
    public static func armor(_ binary: Data) throws -> String {
        try AgeFFI.withBytes(of: binary) { bytes, count in
            var output: UnsafeMutablePointer<CChar>?
            var error: UnsafeMutablePointer<CChar>?
            let status = ageswift_armor(bytes, UInt(count), &output, &error)
            defer { AgeFFI.freeString(error) }
            try AgeError.throwIfFailure(status, error)
            guard let output else {
                throw AgeError.backendFailure("armor returned no output")
            }
            defer { AgeFFI.freeString(output) }
            return String(cString: output)
        }
    }

    /// Decodes an age ASCII armor file back to the binary format.
    ///
    /// Strictly requires armored input: binary age files and anything else
    /// throw ``AgeError/invalidFormat``, as does malformed armor (invalid
    /// base64, missing END marker, non-canonical encoding). Whitespace
    /// around the armored block is ignored. The decoded output is
    /// structurally validated before it is returned; nothing is decrypted.
    /// - Throws: ``AgeError/invalidFormat`` if `armored` is not a valid
    ///   armored age file.
    @discardableResult
    public static func dearmor(_ armored: String) throws -> Data {
        try armored.withCString { armoredCString in
            var output = ageswift_bytes()
            var error: UnsafeMutablePointer<CChar>?
            let status = ageswift_dearmor(armoredCString, &output, &error)
            defer { AgeFFI.freeString(error) }
            try AgeError.throwIfFailure(status, error)
            return try AgeFFI.copyAndFree(output)
        }
    }
}
