//! Scomm OpenPGP types and provider contract.
//!
//! This crate must not depend on Sequoia (or any other OpenPGP engine).

mod error;
mod provider;
mod types;

pub use error::{OpenPgpError, Result};
pub use provider::OpenPgpProvider;
pub use types::*;

/// FFI / Dart ABI version. Bump when the C ABI breaks.
pub const ABI_VERSION: u32 = 1;
