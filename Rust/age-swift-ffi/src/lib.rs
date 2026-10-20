//! age-swift-ffi: a minimal C ABI over the Rust [`age`] crate, consumed by
//! the AgeSwift Swift package. See `include/age_swift_ffi.h` for the
//! documented contract and ownership rules.
//!
//! Layering: `api` (core operations) -> `ffi` (C boundary). Nothing in this
//! crate implements cryptography itself.

mod api;
mod error;
pub mod ffi;

pub use ffi::{AgeswiftBytes, AgeswiftStatus};
