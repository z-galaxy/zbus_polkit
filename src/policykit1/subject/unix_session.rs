//! The details of a `unix-session` subject.

use serde::{Deserialize, Serialize};
use zbus::{as_variant, Type};

use crate::policykit1::text::Text;

/// The details of a `unix-session` subject.
// zbus's dict derives do not take a type with a lifetime, so this goes through serde's, which
// encode a struct as a dictionary when that is its signature.
#[derive(Debug, Serialize, Deserialize, Type)]
#[zbus(signature = "a{sv}")]
pub(super) struct UnixSession<'a> {
    /// The identifier of the session, as the login manager knows it.
    #[serde(rename = "session-id", borrow, with = "as_variant")]
    pub(super) session_id: Text<'a>,
}
