import Foundation
import Testing
@testable import AgeSwift

/// Locates the external tools used by the interoperability tests.
enum InteropTooling {
    static let ageCandidates = [
        "/opt/homebrew/bin/age",
        "/usr/local/bin/age",
        "/opt/local/bin/age",
        "/usr/bin/age",
    ]
    static let expectPath = "/usr/bin/expect"

    static var agePath: String? {
        ageCandidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    static var expectAvailable: Bool {
        FileManager.default.isExecutableFile(atPath: expectPath)
    }
}

/// Interoperability with the standard `age` CLI (age-encryption.org, v1.3.x).
///
/// - X25519 tests need the `age` binary on one of the known paths.
/// - Passphrase tests additionally need `/usr/bin/expect`, because the CLI
///   deliberately only reads passphrases from a terminal.
///
/// When a tool is missing the tests are reported as *skipped*, not passed;
/// install with `brew install age` to run the full suite.
@Suite(.serialized)
struct CLIInteropTests {

    @Test(.enabled(if: InteropTooling.agePath != nil))
    func ageswiftEncryptsAgeCLIDecrypts() throws {
        let age = try #require(InteropTooling.agePath).description
        let scratch = try ScratchDirectory()

        let identity = try AgeIdentity.generate()
        var plaintext = Data("encrypted by AgeSwift, decrypted by the age CLI".utf8)
        plaintext.append(Data(repeating: 0, count: 64))

        let encrypted = try Age.encrypt(plaintext, recipients: [identity.recipient])
        try scratch.write(encrypted, to: "encrypted.age")
        try scratch.write(Data(identity.serialized.utf8), to: "key.txt")

        let output = try ProcessRunner.run(
            executable: age,
            arguments: ["-d", "-i", "key.txt", "-o", "out.bin", "encrypted.age"],
            currentDirectory: scratch.path
        )
        #expect(output.successful, "age CLI failed: \(String(data: output.stderr, encoding: .utf8) ?? "")")
        #expect(try scratch.read("out.bin") == plaintext)
    }

    @Test(.enabled(if: InteropTooling.agePath != nil))
    func ageCLIEncryptsAgeswiftDecrypts() throws {
        let age = try #require(InteropTooling.agePath).description
        let scratch = try ScratchDirectory()

        let identity = try AgeIdentity.generate()
        var plaintext = Data("encrypted by the age CLI, decrypted by AgeSwift".utf8)
        plaintext.append(contentsOf: [0x00, 0xFF, 0x00, 0xFF])
        try scratch.write(plaintext, to: "plain.bin")

        let output = try ProcessRunner.run(
            executable: age,
            arguments: ["-e", "-r", identity.recipient.serialized, "-o", "encrypted.age", "plain.bin"],
            currentDirectory: scratch.path
        )
        #expect(output.successful, "age CLI failed: \(String(data: output.stderr, encoding: .utf8) ?? "")")

        let encrypted = try scratch.read("encrypted.age")
        #expect(try Age.decrypt(encrypted, identities: [identity]) == plaintext)
    }

    @Test(.enabled(if: InteropTooling.agePath != nil && InteropTooling.expectAvailable))
    func ageswiftPassphraseEncryptsAgeCLIDecrypts() throws {
        let age = try #require(InteropTooling.agePath).description
        let scratch = try ScratchDirectory()

        let passphrase = "interop test passphrase"
        let plaintext = Data("passphrase file from AgeSwift to the age CLI".utf8)

        let encrypted = try Age.encrypt(plaintext, passphrase: passphrase)
        try scratch.write(encrypted, to: "encrypted.age")

        try scratch.write(Data(expectScript(execute: age,
                                            arguments: ["-d", "-o", "out.bin", "encrypted.age"],
                                            passphrase: passphrase).utf8),
                          to: "decrypt.exp")

        let output = try ProcessRunner.run(
            executable: InteropTooling.expectPath,
            arguments: ["decrypt.exp"],
            currentDirectory: scratch.path
        )
        #expect(output.successful, "expect/age failed: \(String(data: output.stderr, encoding: .utf8) ?? "")")
        #expect(try scratch.read("out.bin") == plaintext)
    }

    @Test(.enabled(if: InteropTooling.agePath != nil && InteropTooling.expectAvailable))
    func ageCLIPassphraseEncryptsAgeswiftDecrypts() throws {
        let age = try #require(InteropTooling.agePath).description
        let scratch = try ScratchDirectory()

        let passphrase = "another interop passphrase"
        let plaintext = Data("passphrase file from the age CLI to AgeSwift".utf8)
        try scratch.write(plaintext, to: "plain.bin")

        // -p is required: unlike `age -d`, `age -e` does not fall back to
        // passphrase mode when no recipient is specified.
        try scratch.write(Data(expectScript(execute: age,
                                            arguments: ["-e", "-p", "-o", "encrypted.age", "plain.bin"],
                                            passphrase: passphrase).utf8),
                          to: "encrypt.exp")

        let output = try ProcessRunner.run(
            executable: InteropTooling.expectPath,
            arguments: ["encrypt.exp"],
            currentDirectory: scratch.path
        )
        #expect(output.successful, "expect/age failed: \(String(data: output.stderr, encoding: .utf8) ?? "")")

        let encrypted = try scratch.read("encrypted.age")
        #expect(try Age.decrypt(encrypted, passphrase: passphrase) == plaintext)
        // And the wrong passphrase is rejected on both sides' files.
        #expect(throws: AgeError.noMatchingKey) {
            _ = try Age.decrypt(encrypted, passphrase: "wrong")
        }
    }

    // ------------------------------------------------------------ helpers

    /// The CLI reads passphrases only from a terminal, so we drive it through
    /// /usr/bin/expect with a pseudo-tty. Every "assphrase" prompt is
    /// answered with the same string (age asks twice when encrypting).
    private func expectScript(execute: String, arguments: [String], passphrase: String) -> String {
        let safePassphrase = passphrase.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let commandLine = ([execute] + arguments).map { "\"\($0)\"" }.joined(separator: " ")
        return """
        set timeout 60
        spawn \(commandLine)
        expect {
            -re "assphrase" { send "\(safePassphrase)\r"; exp_continue }
            eof
        }
        catch wait result
        exit [lindex $result 3]
        """
    }
}

/// Per-test scratch directory that is removed on deinit.
private final class ScratchDirectory {
    let path: String

    init() throws {
        path = NSTemporaryDirectory() + "ageswift-interop-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(atPath: path) }

    func write(_ data: Data, to name: String) throws {
        try data.write(to: URL(fileURLWithPath: path).appendingPathComponent(name))
    }

    func read(_ name: String) throws -> Data {
        try Data(contentsOf: URL(fileURLWithPath: path).appendingPathComponent(name))
    }
}
