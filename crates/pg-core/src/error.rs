use std::fmt;

/// Every failure in PhoneGate maps to one of these. Callers on the accept path treat *any* error
/// as a denial (Constitution IV: fail-secure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Malformed canonical encoding or field value.
    Decode(&'static str),
    /// A cryptographic operation failed (bad key, AEAD failure, RNG failure).
    Crypto(&'static str),
    /// A signature, MAC, hash binding or identity check failed.
    Verify(&'static str),
    /// The message or request is outside its validity window.
    Expired,
    /// The message id / nonce / request was already consumed.
    Replay,
    /// Operation not valid in the current state.
    State(&'static str),
    /// Local storage or IPC failure.
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode(m) => write!(f, "decode error: {m}"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
            Error::Verify(m) => write!(f, "verification failed: {m}"),
            Error::Expired => write!(f, "expired"),
            Error::Replay => write!(f, "replayed"),
            Error::State(m) => write!(f, "invalid state: {m}"),
            Error::Io(m) => write!(f, "io error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
