//! Identities used by polkit to specify who may authenticate.

mod unix_group;
mod unix_netgroup;
mod unix_user;

use std::{borrow::Cow, collections::HashMap};

use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;
use zbus::{OwnedVariant, Str, Type};

use self::{unix_group::UnixGroup, unix_netgroup::UnixNetgroup, unix_user::UnixUser};

/// An identity polkit can authenticate as: a UNIX user, group or netgroup.
///
/// The daemon hands an authentication agent the identities that may authenticate for an action,
/// and its helper names the one that did.
///
/// On the wire an identity is a kind string and a dictionary of details whose contents depend on
/// that kind. The constructors here build the kinds polkit documents. An identity of a kind this
/// crate does not know about, or whose details are not the ones it expects, is kept as it
/// arrived, so a newer polkit stays readable.
///
/// The text in one can be borrowed, so neither building an identity to send nor decoding one that
/// was received has to allocate for it. [`into_owned`](Self::into_owned) gives any identity the
/// `'static` lifetime.
#[derive(Debug, Clone, PartialEq, Type, Serialize, Deserialize)]
#[zbus(signature = "(sa{sv})")]
#[serde(transparent)]
pub struct Identity<'a>(#[serde(borrow)] Kind<'a>);

assert_impl_all!(Identity<'_>: Send, Sync, Unpin);

impl<'a> Identity<'a> {
    /// The kind this identity is sent as, e.g. `unix-user`.
    pub fn kind(&self) -> &str {
        match &self.0 {
            Kind::UnixUser(_) => UNIX_USER,
            Kind::UnixGroup(_) => UNIX_GROUP,
            Kind::UnixNetgroup(_) => UNIX_NETGROUP,
            Kind::Other(raw) => &raw.identity_kind,
        }
    }

    /// The user's ID, if this is a `unix-user`.
    pub fn uid(&self) -> Option<u32> {
        match &self.0 {
            Kind::UnixUser(user) => Some(user.uid),
            _ => None,
        }
    }

    /// The group's ID, if this is a `unix-group`.
    pub fn gid(&self) -> Option<u32> {
        match &self.0 {
            Kind::UnixGroup(group) => Some(group.gid),
            _ => None,
        }
    }

    /// The netgroup's name, if this is a `unix-netgroup`.
    pub fn netgroup(&self) -> Option<&str> {
        match &self.0 {
            Kind::UnixNetgroup(netgroup) => Some(&netgroup.name),
            _ => None,
        }
    }

    /// Create an `Identity` for the UNIX user with `uid`.
    pub fn new_for_unix_user(uid: u32) -> Self {
        Self(Kind::UnixUser(UnixUser { uid }))
    }

    /// Create an `Identity` for the UNIX group with `gid`.
    pub fn new_for_unix_group(gid: u32) -> Self {
        Self(Kind::UnixGroup(UnixGroup { gid }))
    }

    /// Create an `Identity` for the UNIX netgroup called `name`.
    pub fn new_for_unix_netgroup(name: impl Into<Cow<'a, str>>) -> Self {
        Self(Kind::UnixNetgroup(UnixNetgroup {
            name: name.into().into(),
        }))
    }

    /// This identity with all of its text owned, so that it borrows from nothing.
    pub fn into_owned(self) -> Identity<'static> {
        Identity(match self.0 {
            Kind::UnixUser(user) => Kind::UnixUser(user),
            Kind::UnixGroup(group) => Kind::UnixGroup(group),
            Kind::UnixNetgroup(UnixNetgroup { name }) => Kind::UnixNetgroup(UnixNetgroup {
                name: name.into_owned(),
            }),
            Kind::Other(Raw {
                identity_kind,
                identity_details,
            }) => Kind::Other(Raw {
                identity_kind: identity_kind.into_owned(),
                identity_details: identity_details
                    .into_iter()
                    .map(|(key, value)| (key.into_owned(), value))
                    .collect(),
            }),
        })
    }
}

/// The kinds of identity polkit documents, each with its details, and whatever else arrived.
///
/// Adjacent tagging is the `(kind, details)` pair polkit reads: a struct of two fields, which
/// D-Bus sends as a sequence and a self-describing format as a map, in either order. Serde
/// handles the buffering needed to deserialize the fields in either order.
#[derive(Debug, Clone, PartialEq, Type, Serialize, Deserialize)]
#[zbus(signature = "(sa{sv})")]
#[serde(tag = "identity_kind", content = "identity_details")]
enum Kind<'a> {
    #[serde(rename = "unix-user")]
    UnixUser(UnixUser),

    #[serde(rename = "unix-group")]
    UnixGroup(UnixGroup),

    #[serde(rename = "unix-netgroup")]
    UnixNetgroup(#[serde(borrow)] UnixNetgroup<'a>),

    /// Tried once none of the above matched, so its kind is either one this crate has no struct
    /// for or a known one whose details did not decode. Both are kept as they arrived: the caller
    /// still sees the kind, and nothing polkit sent is lost.
    #[serde(untagged)]
    Other(#[serde(borrow)] Raw<'a>),
}

/// An identity as it is on the wire, for a kind this crate has no struct for.
#[derive(Debug, Clone, PartialEq, Type, Serialize, Deserialize)]
struct Raw<'a> {
    #[serde(borrow)]
    identity_kind: Str<'a>,
    #[serde(borrow)]
    identity_details: HashMap<Str<'a>, OwnedVariant>,
}

const UNIX_USER: &str = "unix-user";
const UNIX_GROUP: &str = "unix-group";
const UNIX_NETGROUP: &str = "unix-netgroup";

#[cfg(test)]
mod tests {
    use zbus::{
        wire::{serialized::Context, to_bytes, LE},
        Variant,
    };

    use super::*;

    #[test]
    fn identities_send_the_details_polkit_reads() {
        let (kind, sent) = sent_as(&Identity::new_for_unix_user(1000));
        assert_eq!(kind, "unix-user");
        assert_eq!(sent.len(), 1);
        // polkit reads `uid` and `gid` as unsigned 32-bit integers.
        assert_eq!(*sent["uid"], Variant::U32(1000));

        let (kind, sent) = sent_as(&Identity::new_for_unix_group(27));
        assert_eq!(kind, "unix-group");
        assert_eq!(sent.len(), 1);
        assert_eq!(*sent["gid"], Variant::U32(27));

        let (kind, sent) = sent_as(&Identity::new_for_unix_netgroup("admins"));
        assert_eq!(kind, "unix-netgroup");
        assert_eq!(sent.len(), 1);
        assert_eq!(*sent["name"], Variant::from("admins"));
    }

    #[test]
    fn identity_borrows_its_text_until_it_is_made_owned() {
        let name = String::from("admins");
        let identity = Identity::new_for_unix_netgroup(name.as_str());
        assert!(std::ptr::eq(identity.netgroup().unwrap(), name.as_str()));

        let owned: Identity<'static> = identity.clone().into_owned();
        assert_eq!(owned, identity);
        assert!(!std::ptr::eq(owned.netgroup().unwrap(), name.as_str()));
    }

    #[test]
    fn identity_borrows_the_text_it_is_decoded_from() {
        let context = Context::new(LE, 0);
        let within = |bytes: &[u8], text: &str| bytes.as_ptr_range().contains(&text.as_ptr());

        let details = HashMap::from([("name", Variant::from("admins"))]);
        let encoded = to_bytes(context, &("unix-netgroup", details)).unwrap();
        let netgroup: Identity<'_> = encoded.deserialize().unwrap().0;
        assert!(within(&encoded, netgroup.netgroup().unwrap()));

        let details = HashMap::from([("name", Variant::from("operator"))]);
        let encoded = to_bytes(context, &("unix-role", details)).unwrap();
        let role: Identity<'_> = encoded.deserialize().unwrap().0;
        assert!(within(&encoded, role.kind()));
        let Kind::Other(raw) = &role.0 else {
            panic!("expected an unknown kind to be kept, got {role:?}");
        };
        assert!(raw.identity_details.keys().all(|key| within(&encoded, key)));
    }

    #[test]
    fn identity_decodes_the_details_of_the_kind_it_was_sent_as() {
        // A key this crate does not know about cannot be an error, or a future polkit would stop
        // being readable.
        let user = received_as(
            "unix-user",
            [
                ("uid", Variant::U32(1000)),
                ("something-new", Variant::from("ignore me")),
            ],
        );
        assert_eq!(user.kind(), "unix-user");
        assert_eq!(user.uid(), Some(1000));
        assert_eq!(user.gid(), None);
        assert_eq!(user.netgroup(), None);

        let group = received_as("unix-group", [("gid", Variant::U32(27))]);
        assert_eq!(group.kind(), "unix-group");
        assert_eq!(group.gid(), Some(27));
        assert_eq!(group.uid(), None);

        let netgroup = received_as("unix-netgroup", [("name", Variant::from("admins"))]);
        assert_eq!(netgroup.kind(), "unix-netgroup");
        assert_eq!(netgroup.netgroup(), Some("admins"));
        assert_eq!(netgroup.gid(), None);
    }

    #[test]
    fn identity_keeps_a_kind_it_does_not_know_as_it_arrived() {
        let identity = received_as("unix-role", [("name", Variant::from("operator"))]);

        assert_eq!(identity.kind(), "unix-role");
        assert_eq!(identity.uid(), None);
        let Kind::Other(raw) = &identity.0 else {
            panic!("expected an unknown kind to be kept, got {identity:?}");
        };
        assert_eq!(
            *raw.identity_details[&Str::from("name")],
            Variant::from("operator")
        );

        let (kind, sent) = sent_as(&identity);
        assert_eq!(kind, "unix-role");
        assert_eq!(*sent["name"], Variant::from("operator"));
    }

    // Serde falls back to `Kind::Other` whenever no tagged variant decoded, so a known kind whose
    // details are not what this crate expects lands there too. It is kept rather than refused:
    // the caller still sees the kind, and nothing polkit sent is lost.
    #[test]
    fn identity_keeps_a_known_kind_whose_details_do_not_decode() {
        let identity = received_as("unix-user", [("uid", Variant::from("not a uid"))]);

        assert_eq!(identity.kind(), "unix-user");
        assert_eq!(identity.uid(), None);
        let Kind::Other(raw) = &identity.0 else {
            panic!("expected the identity to be kept as it arrived, got {identity:?}");
        };
        assert_eq!(
            *raw.identity_details[&Str::from("uid")],
            Variant::from("not a uid")
        );
    }

    // D-Bus sends the `(kind, details)` pair as a sequence and a self-describing format as a map,
    // whose fields can come in either order. Both have to decode, or an `Identity` cannot be read
    // back out of anything it was written to.
    #[test]
    fn identity_round_trips_through_a_self_describing_format() {
        let user = Identity::new_for_unix_user(1000);
        let kind_first = serde_json::to_string(&user).unwrap();
        let details_first = serde_json::to_string(&serde_json::to_value(&user).unwrap()).unwrap();
        assert_ne!(kind_first, details_first);

        for json in [kind_first, details_first] {
            assert_eq!(serde_json::from_str::<Identity<'_>>(&json).unwrap(), user);
        }
    }

    // Signatures as documented in the polkit D-Bus API reference:
    // https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html
    #[test]
    fn wire_signatures_match_polkit() {
        assert_eq!(Identity::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(Kind::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(Raw::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(UnixUser::SIGNATURE.to_string(), "a{sv}");
        assert_eq!(UnixGroup::SIGNATURE.to_string(), "a{sv}");
        assert_eq!(UnixNetgroup::SIGNATURE.to_string(), "a{sv}");
    }

    /// The `(kind, details)` pair `identity` is sent as, read back off the wire.
    fn sent_as(identity: &Identity<'_>) -> (String, HashMap<String, OwnedVariant>) {
        let encoded = to_bytes(Context::new(LE, 0), identity).expect("serialize the identity");

        encoded
            .deserialize()
            .expect("decode the identity as the types polkit reads")
            .0
    }

    /// An `Identity` decoded from the `(kind, details)` pair an authority would send.
    fn received_as<const N: usize>(
        kind: &str,
        details: [(&str, Variant<'_>); N],
    ) -> Identity<'static> {
        let details: HashMap<String, OwnedVariant> = details
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.try_into().unwrap()))
            .collect();
        let encoded =
            to_bytes(Context::new(LE, 0), &(kind.to_string(), details)).expect("serialize details");

        encoded
            .deserialize::<Identity<'_>>()
            .expect("decode an identity")
            .0
            .into_owned()
    }
}
