// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AgeSwift",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "AgeSwift", targets: ["AgeSwift"])
    ],
    targets: [
        // Prebuilt by Scripts/build-xcframework.sh (from the Rust sources in
        // Rust/age-swift-ffi). The artifact is gitignored; run the script once
        // after cloning before invoking SwiftPM. See README.md.
        .binaryTarget(name: "AgeSwiftFFI", path: "Artifacts/AgeSwiftFFI.xcframework"),
        .target(name: "AgeSwift", dependencies: ["AgeSwiftFFI"]),
        .testTarget(name: "AgeSwiftTests", dependencies: ["AgeSwift"]),
    ],
    swiftLanguageModes: [.v6]
)
