# AgeSwift

Swift bindings for the [age](https://age-encryption.org/) file encryption
format, backed by the Rust [`age` crate](https://crates.io/crates/age) from
the [str4d/rage](https://github.com/str4d/rage) project.

AgeSwift lets macOS applications encrypt and decrypt standard age files with
a small, idiomatic Swift API — without reimplementing any cryptography or
file-format logic in Swift.

> **AgeSwift is a binding to an existing, mature Rust implementation.** It is
> *not* an independent cryptographic implementation, and it has **not**
> undergone an external security audit. All cryptographic decisions (algorithms,
> KDF parameters, work factors) are delegated to the upstream `age` crate.

## Status

- **Platform:** macOS 13+ on Apple Silicon (`aarch64-apple-darwin`) and Intel
  (`x86_64-apple-darwin`). The architecture permits future iOS support; iOS
  packaging is intentionally out of scope for the initial milestone.
- **Features:** X25519 recipient encryption, scrypt passphrase encryption,
  in-memory `Data`-based API, binary (non-armored) age v1 files.
- **Not implemented (by design, initial milestone):** SSH keys, plugins,
  ASCII armor, Keychain integration, streaming/file APIs, async APIs.

## Architecture

Three layers, each independently testable:

```
┌──────────────────────────────────────────────┐
│  AgeSwift (Swift)                            │  idiomatic API, Data-based,
│  Age / AgeIdentity / AgeRecipient / AgeError │  Sendable value types
├──────────────────────────────────────────────┤
│  age-swift-ffi (C ABI, Rust)                 │  stable extern "C" surface,
│  include/age_swift_ffi.h                     │  explicit ownership, no
│                                              │  panics across the boundary
├──────────────────────────────────────────────┤
│  age crate (Rust, upstream)                  │  all cryptography and the
│  x25519 + scrypt, age v1 format              │  age v1 file format
└──────────────────────────────────────────────┘
```

The FFI layer is hand-written (`Rust/age-swift-ffi/`): the API surface is
small enough that a bindings framework would add complexity without benefit.
Ownership rules are explicit — Rust-allocated buffers are released only via
`ageswift_free_bytes` / `ageswift_free_string`, and every entry point is
wrapped in `catch_unwind` so Rust panics never cross into Swift.

## Prerequisites

- **macOS** with **Xcode 16+** (Swift 6 language mode is used) and its
  command line tools.
- **Rust** (stable, ≥ 1.85) via [rustup](https://rustup.rs), plus the two
  Apple targets:

  ```sh
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  ```

- *Optional:* the [`age` CLI](https://github.com/FiloSottile/age)
  (`brew install age`) so the interoperability tests actually run instead of
  being skipped.

## Building from source

The Swift package links a prebuilt XCFramework that is **generated from the
Rust sources in this repository** (never fetched from anyone's server). After
cloning, run the build script once; SwiftPM picks up the artifact from
`Artifacts/`:

```sh
git clone <this repository>
cd AgeSwift
./Scripts/build-xcframework.sh     # builds both archs, creates Artifacts/AgeSwiftFFI.xcframework
swift test                         # runs the Swift + interoperability tests
```

The script is the only build entry point you need: it runs `cargo build` for
`aarch64-apple-darwin` and `x86_64-apple-darwin`, `lipo`s them into a fat
static library, and wraps it (with the C header and module map) into an
XCFramework. `Artifacts/` is gitignored; rebuild any time with the same
command (`--debug` for an unoptimized Rust build while iterating).

Rust unit/FFI tests:

```sh
cargo test --manifest-path Rust/age-swift-ffi/Cargo.toml
```

### Using AgeSwift in an application

Until a tagged binary release exists (see roadmap), consume AgeSwift as a
**local Swift package**: add the local folder as a package dependency in
Xcode (or `.package(path:)` in your `Package.swift`), run
`Scripts/build-xcframework.sh` once on each machine that builds, and link
the `AgeSwift` library target. No binary is downloaded from this project's
maintainers, and the full source-build path above always remains available.

## Usage

### X25519 recipients

```swift
import AgeSwift

let identity = try AgeIdentity.generate()      // holds "AGE-SECRET-KEY-1..."
let recipient = identity.recipient             // public "age1..." string

let plaintext = Data("Hello AgeSwift".utf8)
let encrypted = try Age.encrypt(plaintext, recipients: [recipient])
let decrypted = try Age.decrypt(encrypted, identities: [identity])
// decrypted == plaintext
```

Encrypt for several recipients; any one of them (plus anyone holding a
matching key) can decrypt:

```swift
let encrypted = try Age.encrypt(plaintext, recipients: [alice.recipient, bob.recipient])
```

### Passphrase (scrypt) mode

Uses age's standard scrypt recipient with its default ~1-second work factor.
AgeSwift never selects custom KDF parameters.

```swift
let encrypted = try Age.encrypt(plaintext, passphrase: "a strong passphrase")
let decrypted = try Age.decrypt(encrypted, passphrase: "a strong passphrase")
```

Passphrase operations deliberately cost about a second of CPU — keep them off
the main thread.

### Parsing existing keys

```swift
let identity = try AgeIdentity(string: secretKeyString)   // "AGE-SECRET-KEY-1..."
let recipient = try AgeRecipient(string: recipientString) // "age1..."
```

`AgeIdentity.serialized` is the explicit way to access the secret string —
`description`/`debugDescription` are redacted on purpose. Treat
`serialized` like a password: AgeSwift does not store keys anywhere.

### Interoperating with the `age` CLI

```sh
# AgeSwift-encrypted file, decrypt with the standard CLI:
age -d -i key.txt -o plaintext.txt encrypted.age   # key.txt contains the AGE-SECRET-KEY-1... string

# CLI-encrypted file, decrypt with AgeSwift:
age -e -r age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -o encrypted.age plaintext.txt
# then: try Age.decrypt(encryptedData, identities: [identity])

# Passphrase mode (the CLI always prompts on the terminal):
age -e -p -o encrypted.age plaintext.txt
age -d -o plaintext.txt encrypted.age
```

All four directions (Swift→CLI and CLI→Swift, for both X25519 and
passphrase mode) are covered by automated tests against the real `age`
binary.

## Error handling

`AgeError` maps FFI status codes to typed Swift errors:

| Case | Meaning |
|---|---|
| `.invalidArgument(String)` | Malformed arguments (e.g. empty recipient list) |
| `.invalidIdentity` | Not a valid `AGE-SECRET-KEY-1...` string |
| `.invalidRecipient` | Not a valid `age1...` string |
| `.encryptionFailed(String)` | Encryption backend failure |
| `.invalidFormat` | Input is not an age file (bad magic/header) |
| `.noMatchingKey` | Wrong passphrase, or none of the identities match |
| `.decryptionFailed(String)` | Corrupted or truncated payload |
| `.backendFailure(String)` | Unexpected backend result (never expected) |

Error messages never contain key material, passphrases, or plaintext.

## Security considerations

- **Not audited.** AgeSwift has not had an external security review. The
  underlying `age` crate is widely used and battle-tested, but the binding
  layer (this repository) is new code.
- **Memory erasure is best-effort and incomplete.** Rust-side secrets are
  held in `age`'s `SecretString` (zeroized on drop) and released promptly,
  but Swift `String`/`Data` cannot be zeroized — passphrase and identity
  copies made by Swift, Foundation, or the OS may persist in memory. Design
  assuming plaintext and keys can remain in process memory.
- **FFI discipline.** Buffer ownership is explicit and one-directional
  (Rust allocates, Rust frees via dedicated functions). Panics are caught at
  the boundary. Null and zero-length inputs are handled. See
  `Rust/age-swift-ffi/src/ffi.rs` for the enforced invariants.
- **No logging of secrets** by the library. `AgeIdentity` redacts its
  `description`; serialization is deliberately explicit.
- **scrypt cost.** Both passphrase encryption and (wrong-passphrase)
  decryption perform ~1 second of scrypt work per the age standard; this is
  intentional DoS resistance, not a bug.
- The library imposes **no code-signing, Keychain, or entitlement
  requirements** on applications that link it.

## Repository layout

```
AgeSwift/
├── Package.swift                  # SwiftPM manifest (binaryTarget + AgeSwift)
├── Sources/AgeSwift/              # public Swift API
├── Tests/AgeSwiftTests/           # Swift Testing suite incl. CLI interop
├── Rust/age-swift-ffi/            # Rust crate: core + C ABI (Cargo.lock committed)
│   ├── include/age_swift_ffi.h    # the C contract
│   └── tests/ffi.rs               # FFI-level Rust tests
├── Scripts/build-xcframework.sh   # reproducible source build of the artifact
└── .github/workflows/ci.yml       # cargo test + xcframework + swift test
```

## Known limitations & roadmap

Current limitations:

- macOS only (iOS packaging not built yet; nothing in the code is
  macOS-specific).
- In-memory APIs only — no streaming for very large files (the age crate's
  streaming reader/writer can be exposed later behind the same FFI pattern).
- No SSH identities, plugins, ASCII armor, or recipient files.
- `swift test` on Intel Macs runs the library through Rosetta-free native
  code but the CI matrix currently exercises arm64 hosts; the Intel slice is
  cross-compiled and unit-tested via the same Rust tests.

Roadmap ideas (in rough priority order): tagged releases with a checksummed
remote binary target (keeping the source build path); iOS/tvOS/watchOS
slices; armor support; SSH recipient support; streaming APIs.

## License

AgeSwift is dual-licensed under the [MIT](LICENSE-MIT) and
[Apache-2.0](LICENSE-APACHE) licenses — the same terms as the upstream
[`age` crate](https://github.com/str4d/rage). You may use it under either
license, at your option.
