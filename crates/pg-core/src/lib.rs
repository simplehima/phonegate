//! # pg-core
//!
//! The single Rust implementation of the PhoneGate v1 protocol
//! (`docs/specs/001-phone-approved-unlock/contracts/protocol.md`). It is shared by the relay, the
//! Windows agent, the credential provider, the companion app, and the test simulator.
//!
//! Security rests only on keys generated on the user's devices (Constitution I). Nothing in this
//! crate is secret.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod attestation;
pub mod crypto;
pub mod encoding;
pub mod envelope;
pub mod health;
pub mod error;
pub mod ipc;
pub mod messages;
pub mod offline;
pub mod pairing;
pub mod recovery;
pub mod signer;
pub mod store;

#[cfg(feature = "client")]
pub mod relay_client;

pub use error::{Error, Result};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
