//! The identity polkit names who may authenticate by, as it is sent and received.

mod unix_group;
mod unix_netgroup;
mod unix_user;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;
use zbus::{OwnedVariant, Type};

use self::{unix_group::UnixGroup, unix_netgroup::UnixNetgroup, unix_user::UnixUser};

/// An identity polkit can authenticate as: a UNIX user, group or netgroup.
///
/// This is the owned counterpart of [`Identity`](super::Identity), which only encodes. The daemon
/// hands an authentication agent the identities that may authenticate for an action, and this is
/// the type they arrive as.
///
/// On the wire an identity is a kind string and a dictionary of details whose contents depend on
/// that kind. The constructors here build the kinds polkit documents. An identity of a kind this
/// crate does not know about, or whose details are not the ones it expects, is kept as it
/// arrived, so a newer polkit stays readable.
#[derive(Debug, Clone, PartialEq, Type, Serialize, Deserialize)]
#[zbus(signature = "(sa{sv})")]
#[serde(transparent)]
pub struct OwnedIdentity(Kind);

assert_impl_all!(OwnedIdentity: Send, Sync, Unpin);

impl OwnedIdentity {
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

    /// Create an `OwnedIdentity` for the UNIX user with `uid`.
    pub fn new_for_unix_user(uid: u32) -> Self {
        Self(Kind::UnixUser(UnixUser { uid }))
    }

    /// Create an `OwnedIdentity` for the UNIX group with `gid`.
    pub fn new_for_unix_group(gid: u32) -> Self {
        Self(Kind::UnixGroup(UnixGroup { gid }))
    }

    /// Create an `OwnedIdentity` for the UNIX netgroup called `name`.
    pub fn new_for_unix_netgroup(name: impl Into<String>) -> Self {
        Self(Kind::UnixNetgroup(UnixNetgroup { name: name.into() }))
    }
}

/// The kinds of identity polkit documents, each with its details, and whatever else arrived.
///
/// Adjacent tagging is the `(kind, details)` pair polkit reads: a struct of two fields, which
/// D-Bus sends as a sequence and a self-describing format as a map, in either order. Serde only
/// knows how to read the details once it has the kind, and does the buffering that takes itself.
#[derive(Debug, Clone, PartialEq, Type, Serialize, Deserialize)]
#[zbus(signature = "(sa{sv})")]
#[serde(tag = "identity_kind", content = "identity_details")]
enum Kind {
    #[serde(rename = "unix-user")]
    UnixUser(UnixUser),

    #[serde(rename = "unix-group")]
    UnixGroup(UnixGroup),

    #[serde(rename = "unix-netgroup")]
    UnixNetgroup(UnixNetgroup),

    /// Tried once none of the above matched, so its kind is either one this crate has no struct
    /// for or a known one whose details did not decode. Both are kept as they arrived: the caller
    /// still sees the kind, and nothing polkit sent is lost.
    #[serde(untagged)]
    Other(Raw),
}

/// An identity as it is on the wire, for a kind this crate has no struct for.
#[derive(Debug, Clone, PartialEq, Type, Serialize, Deserialize)]
struct Raw {
    identity_kind: String,
    identity_details: HashMap<String, OwnedVariant>,
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
    use crate::policykit1::Identity;

    /// The `(kind, details)` pair `identity` is sent as, read back off the wire.
    fn sent_as(identity: &OwnedIdentity) -> (String, HashMap<String, OwnedVariant>) {
        let encoded = to_bytes(Context::new(LE, 0), identity).expect("serialize the identity");

        encoded
            .deserialize()
            .expect("decode the identity as the types polkit reads")
            .0
    }

    /// An `OwnedIdentity` decoded from the `(kind, details)` pair an authority would send.
    fn received_as<const N: usize>(kind: &str, details: [(&str, Variant<'_>); N]) -> OwnedIdentity {
        let details: HashMap<String, OwnedVariant> = details
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.try_into().unwrap()))
            .collect();
        let encoded =
            to_bytes(Context::new(LE, 0), &(kind.to_string(), details)).expect("serialize details");

        encoded.deserialize().expect("decode an identity").0
    }

    #[test]
    fn identities_send_the_details_polkit_reads() {
        let (kind, sent) = sent_as(&OwnedIdentity::new_for_unix_user(1000));
        assert_eq!(kind, "unix-user");
        assert_eq!(sent.len(), 1);
        // polkit reads `uid` and `gid` as unsigned 32-bit integers.
        assert_eq!(*sent["uid"], Variant::U32(1000));

        let (kind, sent) = sent_as(&OwnedIdentity::new_for_unix_group(27));
        assert_eq!(kind, "unix-group");
        assert_eq!(sent.len(), 1);
        assert_eq!(*sent["gid"], Variant::U32(27));

        let (kind, sent) = sent_as(&OwnedIdentity::new_for_unix_netgroup("admins"));
        assert_eq!(kind, "unix-netgroup");
        assert_eq!(sent.len(), 1);
        assert_eq!(*sent["name"], Variant::from("admins"));
    }

    // `Identity` is what the existing API sends an identity as; an `OwnedIdentity` of the same
    // kind has to be the same bytes.
    #[test]
    fn owned_identity_encodes_like_identity() {
        let ctxt = Context::new(LE, 0);
        let cases = [
            (
                OwnedIdentity::new_for_unix_user(1000),
                "unix-user",
                HashMap::from([("uid", Variant::U32(1000))]),
            ),
            (
                OwnedIdentity::new_for_unix_group(27),
                "unix-group",
                HashMap::from([("gid", Variant::U32(27))]),
            ),
            (
                OwnedIdentity::new_for_unix_netgroup("admins"),
                "unix-netgroup",
                HashMap::from([("name", Variant::from("admins"))]),
            ),
        ];

        for (owned, identity_kind, details) in &cases {
            let borrowed = Identity {
                identity_kind,
                identity_details: details,
            };

            assert_eq!(
                to_bytes(ctxt, owned).unwrap().bytes(),
                to_bytes(ctxt, &borrowed).unwrap().bytes(),
                "{identity_kind}"
            );
        }
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
        assert_eq!(*raw.identity_details["name"], Variant::from("operator"));

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
        assert_eq!(*raw.identity_details["uid"], Variant::from("not a uid"));
    }

    // D-Bus sends the `(kind, details)` pair as a sequence and a self-describing format as a map,
    // whose keys `serde_json::to_value` sorts, putting the details before the kind. All of it has
    // to decode, or an `OwnedIdentity` cannot be read back out of anything it was written to.
    #[test]
    fn identity_round_trips_through_a_self_describing_format() {
        let user = OwnedIdentity::new_for_unix_user(1000);

        for back in [
            serde_json::from_str::<OwnedIdentity>(&serde_json::to_string(&user).unwrap()).unwrap(),
            serde_json::from_value::<OwnedIdentity>(serde_json::to_value(&user).unwrap()).unwrap(),
        ] {
            assert_eq!(back, user);
        }
    }

    // Signatures as documented in the polkit D-Bus API reference:
    // https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html
    #[test]
    fn wire_signatures_match_polkit() {
        assert_eq!(OwnedIdentity::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(Kind::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(Raw::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(UnixUser::SIGNATURE.to_string(), "a{sv}");
        assert_eq!(UnixGroup::SIGNATURE.to_string(), "a{sv}");
        assert_eq!(UnixNetgroup::SIGNATURE.to_string(), "a{sv}");
    }
}
