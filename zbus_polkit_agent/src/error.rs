#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("zbus error")]
    Zbus(#[from] zbus::Error),
    #[error("Session Type Unknown: {0}")]
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
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("Unkownn line {0} from helper")]
    UnknownMessage(String),
}
