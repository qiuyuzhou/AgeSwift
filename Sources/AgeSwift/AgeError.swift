import Foundation
import AgeSwiftFFI

/// Errors thrown by AgeSwift.
public enum AgeError: Error, Equatable, Sendable, CustomStringConvertible {
    /// An argument was malformed (for example, an empty recipient or identity list).
    case invalidArgument(String)
    /// The string is not a valid age secret identity (`AGE-SECRET-KEY-1...`).
    case invalidIdentity
    /// The string is not a valid age recipient (`age1...`).
    case invalidRecipient
    /// Encryption failed in the underlying age implementation.
    case encryptionFailed(String)
    /// The data is not a valid age file in either representation: bad magic
    /// bytes, a malformed header, or malformed ASCII armor. A header that
    /// parses but fails its MAC check (tampered file) is `.decryptionFailed`.
    /// The detail is the secret-free backend description
    /// (e.g. "invalid ASCII armor: ...").
    case invalidFormat(String)
    /// None of the provided identities or passphrases could decrypt the file.
    case noMatchingKey
    /// Decryption failed after the header was parsed: a corrupted or truncated
    /// payload, or a tampered header that fails its MAC check.
    case decryptionFailed(String)
    /// The Rust backend returned an unexpected result (never expected in practice).
    case backendFailure(String)

    /// Human-readable description that never includes key material,
    /// passphrases, or plaintext.
    public var description: String {
        switch self {
        case .invalidArgument(let detail):
            return "invalid argument: \(detail)"
        case .invalidIdentity:
            return "not a valid age secret identity string"
        case .invalidRecipient:
            return "not a valid age recipient string"
        case .encryptionFailed(let detail):
            return "encryption failed: \(detail)"
        case .invalidFormat(let detail):
            // The backend message is already a complete, secret-free
            // description ("input is not a valid age file: ...").
            return detail
        case .noMatchingKey:
            return "no matching identity or passphrase found for this file"
        case .decryptionFailed(let detail):
            return "decryption failed: \(detail)"
        case .backendFailure(let detail):
            return "age backend failure: \(detail)"
        }
    }

    /// Throws the Swift error matching an FFI status code.
    /// `message` is the (secret-free) detail string returned by Rust, if any.
    static func ffiError(status: ageswift_status, message: String?) -> AgeError {
        switch status.rawValue {
        case AGESWIFT_ERR_INVALID_ARGUMENT.rawValue:
            return .invalidArgument(message ?? "unknown")
        case AGESWIFT_ERR_INVALID_IDENTITY.rawValue:
            return .invalidIdentity
        case AGESWIFT_ERR_INVALID_RECIPIENT.rawValue:
            return .invalidRecipient
        case AGESWIFT_ERR_ENCRYPTION_FAILED.rawValue:
            return .encryptionFailed(message ?? "unknown error")
        case AGESWIFT_ERR_DECRYPTION_FAILED.rawValue:
            return .decryptionFailed(message ?? "unknown error")
        case AGESWIFT_ERR_NO_MATCHING_KEY.rawValue:
            return .noMatchingKey
        case AGESWIFT_ERR_INVALID_FORMAT.rawValue:
            return .invalidFormat(message ?? "input is not a valid age file")
        default:
            return .backendFailure("unexpected FFI status \(status.rawValue)\(message.map { ": \($0)" } ?? "")")
        }
    }

    /// Throws when `status` is not `AGESWIFT_OK`; consumes `errorPtr`, i.e.
    /// releases the Rust-allocated message before returning (null on success).
    ///
    /// Ownership: this function is the only owner of `errorPtr`. Callers must
    /// NOT free it afterwards — a second `ageswift_free_string` on the same
    /// pointer is a double free and will crash or corrupt the heap.
    @inline(__always)
    static func throwIfFailure(_ status: ageswift_status,
                               _ errorPtr: UnsafeMutablePointer<CChar>?) throws {
        defer { AgeFFI.freeString(errorPtr) }
        guard status != AGESWIFT_OK else { return }
        throw ffiError(status: status, message: errorPtr.map { String(cString: $0) })
    }
}

/// Internal helpers around the C ABI. Not part of the public API.
enum AgeFFI {
    @inline(__always)
    static func freeString(_ pointer: UnsafeMutablePointer<CChar>?) {
        if let pointer { ageswift_free_string(pointer) }
    }

    /// Takes ownership of a Rust byte buffer, copies it into `Data` while the
    /// buffer is still alive, and releases the Rust allocation. Swift never
    /// retains Rust-owned memory.
    @inline(__always)
    static func copyAndFree(_ buffer: ageswift_bytes) throws -> Data {
        defer { ageswift_free_bytes(buffer) }
        guard buffer.len == 0 else {
            guard let pointer = buffer.ptr else {
                throw AgeError.backendFailure("null buffer with nonzero length")
            }
            return Data(bytes: pointer, count: Int(buffer.len))
        }
        return Data()
    }

    /// Converts a Rust-returned byte buffer that is expected to be UTF-8
    /// text (armored output) into a `String`. Armor is ASCII by construction;
    /// a failure here means the backend misbehaved.
    static func textFromBytes(_ data: Data) throws -> String {
        guard let text = String(data: data, encoding: .utf8) else {
            throw AgeError.backendFailure("armored output was not valid UTF-8")
        }
        return text
    }

    /// `String.withCString` for FFI inputs. Rejects interior NUL bytes: the
    /// C ABI cannot represent them, so the Rust side would silently use only
    /// the prefix before the NUL.
    static func withCString<R>(_ string: String,
                               _ body: (UnsafePointer<CChar>) throws -> R) throws -> R {
        guard !string.utf8.contains(0) else {
            throw AgeError.invalidArgument("string contains a NUL byte")
        }
        return try string.withCString(body)
    }

    /// Runs `body` with a C array of pointers to NUL-terminated copies of
    /// `strings`, keeping the backing storage alive for the duration of the
    /// call without any manual malloc/free.
    static func withCStringsAsArray<R>(_ strings: [String],
                                       _ body: ([UnsafePointer<CChar>?]) throws -> R) rethrows -> R {
        // Flat storage: UTF-8 bytes of every string, each NUL-terminated.
        var flat = [UInt8]()
        flat.reserveCapacity(strings.reduce(0) { $0 + $1.utf8.count + 1 })
        var offsets = [Int]()
        offsets.reserveCapacity(strings.count)
        for string in strings {
            offsets.append(flat.count)
            flat.append(contentsOf: string.utf8)
            flat.append(0)
        }
        return try flat.withUnsafeBufferPointer { storage in
            let base = storage.baseAddress
            let pointers: [UnsafePointer<CChar>?] = offsets.map { offset -> UnsafePointer<CChar>? in
                guard let base else { return nil }
                return UnsafeRawPointer(base + offset).assumingMemoryBound(to: CChar.self)
            }
            return try body(pointers)
        }
    }

    /// Provides `(pointer, length)` for a `Data`'s bytes for the duration of
    /// `body`. The pointer is NULL for empty data, which the FFI accepts
    /// whenever the length is 0.
    @inline(__always)
    static func withBytes<R>(of data: Data,
                             _ body: (UnsafePointer<UInt8>?, Int) throws -> R) rethrows -> R {
        try data.withUnsafeBytes { raw in
            try body(raw.baseAddress?.assumingMemoryBound(to: UInt8.self), raw.count)
        }
    }
}
