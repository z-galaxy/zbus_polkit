//! The details of a `unix-user` identity.

use zbus::{DeserializeDict, SerializeDict, Type};

/// The details of a `unix-user` identity.
#[derive(Debug, Clone, PartialEq, Eq, SerializeDict, DeserializeDict, Type)]
#[zbus(signature = "a{sv}")]
pub(super) struct UnixUser {
    /// The user's ID.
    pub(super) uid: u32,
}
