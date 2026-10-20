# AgeSwift

## Rust formatting

Before committing Rust changes, format the crate in place:

    cargo fmt --manifest-path Rust/age-swift-ffi/Cargo.toml

The pre-commit hook at `Scripts/git-hooks/pre-commit` rejects a commit whose staged `.rs` files leave the crate unformatted. When it fires, run the command above, re-stage, and commit again. Enable the hook once per clone with:

    git config core.hooksPath Scripts/git-hooks
