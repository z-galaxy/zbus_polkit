//! The text of an identity or a subject.

use std::{fmt, ops::Deref, sync::Arc};

use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use zbus::{Basic, Str, Type};

/// A string that borrows from what it is decoded from when that can lend it, as a D-Bus message
/// always can, and owns it otherwise.
///
/// [`Str`] on its own only decodes from text it can borrow, which a format that has to unescape
/// its strings cannot always lend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Type)]
#[zbus(signature = "s")]
#[serde(transparent)]
pub(super) struct Text<'a>(Str<'a>);

// The keys of a D-Bus dictionary have to be basic types.
impl Basic for Text<'_> {
    const SIGNATURE_CHAR: char = Str::SIGNATURE_CHAR;
    const SIGNATURE_STR: &'static str = Str::SIGNATURE_STR;
}

impl Text<'_> {
    pub(super) fn into_owned(self) -> Text<'static> {
        Text(self.0.into_owned())
    }
}

impl<'a> From<Str<'a>> for Text<'a> {
    fn from(text: Str<'a>) -> Self {
        Self(text)
    }
}

impl Deref for Text<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for Text<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Borrowing;

        impl<'de> Visitor<'de> for Borrowing {
            type Value = Text<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_borrowed_str<E>(self, text: &'de str) -> Result<Self::Value, E> {
                Ok(Text(text.into()))
            }

            fn visit_str<E>(self, text: &str) -> Result<Self::Value, E> {
                Ok(Text(Arc::<str>::from(text).into()))
            }
        }

        deserializer.deserialize_str(Borrowing)
    }
}
