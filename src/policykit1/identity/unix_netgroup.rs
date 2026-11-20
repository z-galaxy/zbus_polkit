//! The details of a `unix-netgroup` identity.

use serde::{Deserialize, Serialize};
use zbus::{as_variant, Str, Type};

/// The details of a `unix-netgroup` identity.
// zbus's dict derives do not take a type with a lifetime, so this goes through serde's, which
// encode a struct as a dictionary when that is its signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
#[zbus(signature = "a{sv}")]
pub(super) struct UnixNetgroup<'a> {
    /// The netgroup's name, as NIS or `/etc/netgroup` knows it.
    #[serde(borrow, with = "as_variant")]
    pub(super) name: Str<'a>,
}
