import Foundation

/// Minimal synchronous process runner for the CLI interoperability tests.
struct ProcessRunner {

    struct Output {
        let status: Int32
        let stdout: Data
        let stderr: Data
        var successful: Bool { status == 0 }
    }

    static func run(executable: String,
                    arguments: [String],
                    currentDirectory: String? = nil,
                    standardInput: Data? = nil) throws -> Output {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let currentDirectory { process.currentDirectoryURL = URL(fileURLWithPath: currentDirectory) }

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()
        if let standardInput {
            try stdinPipe.fileHandleForWriting.write(contentsOf: standardInput)
        }
        // Closing the write end signals EOF to the child.
        try? stdinPipe.fileHandleForWriting.close()

        // The child's outputs here are all small (< 64 KiB pipe buffer), so
        // reading after wait cannot deadlock.
        process.waitUntilExit()

        let stdout = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderr = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        return Output(status: process.terminationStatus, stdout: stdout, stderr: stderr)
    }
}
