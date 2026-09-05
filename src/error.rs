use static_assertions::assert_impl_all;

/// The error type for `zbus_polkit`.
///
/// The various errors that can be reported by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O errors.
    #[error("Io Error")]
    Io(#[from] std::io::Error),

    /// Could not parse a number for a Process ID or an User ID.

    #[error("parse int error {0}")]
    ParseInt(#[from] std::num::ParseIntError),

    /// Could not retrieve/deserialize sender header of the message.
    #[error("bad sender {0}")]
    BadSender(zbus::Error),

    /// Missing sender header in the message.
    #[error("missing sender")]
    MissingSender,
    #[error("zbus error")]
    Zbus(#[from] zbus::Error),
    /// Session type Unknown
    #[error("session unknown {0}")]
    SessionUnknown(String),

    #[error("Session Unmatch")]
    SessionUnmatch,
    #[error("Server did not provided important information")]
    SessionInnerError,
    #[error("Nix Error")]
    NixError(#[from] nix::Error),
    #[error("User not found: {0}")]
    UserNotFound(u32),
    #[error("agent polkit path not found")]
    PolkitFileNotFound,
    #[error("Unkownn line {0} from helper")]
    UnknownMessage(String),
}

assert_impl_all!(Error: Send, Sync, Unpin);
