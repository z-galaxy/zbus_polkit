//! The details of a `unix-group` identity.

use zbus::{DeserializeDict, SerializeDict, Type};

/// The details of a `unix-group` identity.
#[derive(Debug, Clone, PartialEq, Eq, SerializeDict, DeserializeDict, Type)]
#[zbus(signature = "a{sv}")]
pub(super) struct UnixGroup {
    /// The group's ID.
    pub(super) gid: u32,
}
