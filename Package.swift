// swift-tools-version: 6.0
import Foundation
import PackageDescription

// The FFI layer is a prebuilt XCFramework built from the Rust sources in
// Rust/age-swift-ffi (entry point: Scripts/build-xcframework.sh). Which copy
// is used answers one question: does a locally built artifact exist?
//
//   - Yes (development machine, after `task build`): use the local
//     Artifacts/AgeSwiftFFI.xcframework — this is the day-to-day dev loop.
//   - No (anyone adding this package by URL): download the zip of the most
//     recent release from GitHub Releases.
//
// `task release VERSION=x.y.z` builds the artifact and updates the two
// releasedBinary* values below in the same run that creates the release.
// Until the first release ships they hold placeholder values (0.0.0).
let localXCFramework = "Artifacts/AgeSwiftFFI.xcframework"

// Updated by `task release` — keep these two lines in this exact shape; the
// release task patches them by regex and verifies the result.
let releasedBinaryURL = "https://github.com/qiuyuzhou/AgeSwift/releases/download/0.1.0/AgeSwiftFFI.xcframework.zip"
let releasedBinaryChecksum = "fcc8c9d0b438252e3c42e67d3087287153d58e1fed3c7d032ba721b2682baac8"

let ffiTarget: Target = FileManager.default.fileExists(atPath: localXCFramework)
    ? .binaryTarget(name: "AgeSwiftFFI", path: localXCFramework)
    : .binaryTarget(
        name: "AgeSwiftFFI",
        url: releasedBinaryURL,
        checksum: releasedBinaryChecksum
    )

let package = Package(
    name: "AgeSwift",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "AgeSwift", targets: ["AgeSwift"])
    ],
    targets: [
        ffiTarget,
        .target(name: "AgeSwift", dependencies: ["AgeSwiftFFI"]),
        .testTarget(name: "AgeSwiftTests", dependencies: ["AgeSwift"]),
    ],
    swiftLanguageModes: [.v6]
)
