//! The details of a `system-bus-name` subject.

use serde::{Deserialize, Serialize};
use zbus::{as_variant, names::UniqueName, Type};

/// The details of a `system-bus-name` subject.
// zbus's dict derives do not take a type with a lifetime, so this goes through serde's, which
// encode a struct as a dictionary when that is its signature.
#[derive(Debug, Serialize, Deserialize, Type)]
#[zbus(signature = "a{sv}")]
pub(super) struct SystemBusName<'a> {
    /// The unique name of the connection that owns the subject.
    #[serde(borrow, with = "as_variant")]
    pub(super) name: UniqueName<'a>,
}
