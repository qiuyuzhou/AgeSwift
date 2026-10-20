#!/usr/bin/env bash
#
# Builds the age-swift-ffi Rust static library for both Apple Silicon and
# Intel, then packs a universal XCFramework into Artifacts/AgeSwiftFFI.xcframework
# for the SwiftPM binary target declared in Package.swift.
#
# Requirements: rustup with the aarch64-apple-darwin and x86_64-apple-darwin
# targets installed, plus Xcode's command line tools.
#
# Usage: ./Scripts/build-xcframework.sh [--debug]
#   --debug  build an unoptimized Rust library for faster iteration

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATE_DIR="$ROOT/Rust/age-swift-ffi"
OUTPUT="$ROOT/Artifacts/AgeSwiftFFI.xcframework"
LIB_NAME="libage_swift_ffi.a"

PROFILE="release"
if [[ "${1:-}" == "--debug" ]]; then
    PROFILE="dev"
fi

TARGETS=(
    "aarch64-apple-darwin"
    "x86_64-apple-darwin"
)

cd "$CRATE_DIR"

mkdir -p target build/universal
SLICES=()
for target in "${TARGETS[@]}"; do
    echo "==> cargo build ($PROFILE, $target)"
    if [[ "$PROFILE" == "dev" ]]; then
        cargo build --target "$target"
    else
        cargo build --release --target "$target"
    fi
    SLICES+=("target/$target/$PROFILE/$LIB_NAME")
done

echo "==> lipo (universal slice)"
lipo -create -output "build/universal/$LIB_NAME" "${SLICES[@]}"

echo "==> xcodebuild -create-xcframework"
rm -rf "$OUTPUT"
mkdir -p "$ROOT/Artifacts"
xcodebuild -create-xcframework \
    -library "build/universal/$LIB_NAME" \
    -headers "include" \
    -output "$OUTPUT"

echo "==> done: $OUTPUT"
