//! The details of a `system-bus-name` subject.

use zbus::{names::OwnedUniqueName, DeserializeDict, SerializeDict, Type};

/// The details of a `system-bus-name` subject.
#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zbus(signature = "a{sv}")]
pub(super) struct SystemBusName {
    /// The unique name of the connection that owns the subject.
    pub(super) name: OwnedUniqueName,
}
