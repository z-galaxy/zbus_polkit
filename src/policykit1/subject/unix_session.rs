//! The details of a `unix-session` subject.

use zbus::{DeserializeDict, SerializeDict, Type};

/// The details of a `unix-session` subject.
#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zbus(signature = "a{sv}")]
pub(super) struct UnixSession {
    /// The identifier of the session, as the login manager knows it.
    #[zbus(rename = "session-id")]
    pub(super) session_id: String,
}
