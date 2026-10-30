//! The details of a `unix-netgroup` identity.

use zbus::{DeserializeDict, SerializeDict, Type};

/// The details of a `unix-netgroup` identity.
#[derive(Debug, Clone, PartialEq, Eq, SerializeDict, DeserializeDict, Type)]
#[zbus(signature = "a{sv}")]
pub(super) struct UnixNetgroup {
    /// The netgroup's name, as NIS or `/etc/netgroup` knows it.
    pub(super) name: String,
}
