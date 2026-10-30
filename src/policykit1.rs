use std::{collections::HashMap, fmt};

use bitflags::{parser, Flags};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use static_assertions::assert_impl_all;
use zbus::{fdo, Basic, OwnedVariant, Type, Variant};

#[cfg(feature = "agent")]
pub mod agent;
mod identity;
pub use identity::OwnedIdentity;
mod subject;
pub use subject::Subject;

/// Flags used in the CheckAuthorization() method.
///
/// This is a [`bitflags`] flag set, sent over the wire as a plain `u32`. Combine flags with `|`,
/// and use [`CheckAuthorizationFlags::empty`] for none of them.
#[derive(
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Type,
    Variant,
    OwnedVariant,
)]
pub struct CheckAuthorizationFlags(u32);

bitflags::bitflags! {
    impl CheckAuthorizationFlags: u32 {
        /// If the Subject can obtain the authorization through authentication, and an
        /// authentication agent is available, then attempt to do so. Note, this means that the
        /// CheckAuthorization() method will block while the user is being asked to authenticate.
        const ALLOW_USER_INTERACTION = 0x01;
    }
}

impl fmt::Debug for CheckAuthorizationFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_flags("CheckAuthorizationFlags", self, f)
    }
}

// So that the flags can be the key of a dictionary.
impl Basic for CheckAuthorizationFlags {
    const SIGNATURE_CHAR: char = u32::SIGNATURE_CHAR;
    const SIGNATURE_STR: &'static str = u32::SIGNATURE_STR;
}

assert_impl_all!(CheckAuthorizationFlags: Send, Sync, Unpin);

/// An enumeration for granting implicit authorizations.
#[repr(u32)]
#[derive(Deserialize_repr, Serialize_repr, Type, Debug, PartialEq, Eq)]
pub enum ImplicitAuthorization {
    /// The Subject is not authorized.
    NotAuthorized = 0,
    /// Authentication is required.
    AuthenticationRequired = 1,
    /// Authentication as an administrator is required.
    AdministratorAuthenticationRequired = 2,
    /// Authentication is required. If the authorization is obtained, it is retained.
    AuthenticationRequiredRetained = 3,
    /// Authentication as an administrator is required. If the authorization is obtained, it is
    /// retained.
    AdministratorAuthenticationRequiredRetained = 4,
    /// The subject is authorized.
    Authorized = 5,
}

assert_impl_all!(ImplicitAuthorization: Send, Sync, Unpin);

/// Flags describing features supported by the Authority implementation.
///
/// This is a [`bitflags`] flag set, sent over the wire as a plain `u32`. A bit that this crate
/// does not name, e.g. one added by a newer polkit, is retained rather than rejected: it shows up
/// in [`AuthorityFeatures::bits`] and in the `Debug` output as a hex number, but matches none of
/// the constants.
#[derive(
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Type,
    Variant,
    OwnedVariant,
)]
pub struct AuthorityFeatures(u32);

bitflags::bitflags! {
    impl AuthorityFeatures: u32 {
        /// The authority supports temporary authorizations that can be obtained through
        /// authentication.
        const TEMPORARY_AUTHORIZATION = 0x01;
    }
}

impl fmt::Debug for AuthorityFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_flags("AuthorityFeatures", self, f)
    }
}

// So that the flags can be the key of a dictionary.
impl Basic for AuthorityFeatures {
    const SIGNATURE_CHAR: char = u32::SIGNATURE_CHAR;
    const SIGNATURE_STR: &'static str = u32::SIGNATURE_STR;
}

assert_impl_all!(AuthorityFeatures: Send, Sync, Unpin);

/// Details of a temporary authorization as provided by the /org/freedesktop/PolicyKit1/Authority
/// object in the system bus.
#[derive(Debug, Type, Deserialize, Serialize)]
pub struct TemporaryAuthorization {
    /// An opaque identifier for the temporary authorization.
    pub id: String,

    /// The action the temporary authorization is for.
    pub action_id: String,

    /// The subject the temporary authorization is for.
    pub subject: Subject,

    /// When the temporary authorization was obtained, in seconds since the Epoch Jan 1, 1970 0:00
    /// UTC. Note that the PolicyKit daemon is using monotonic time internally so the returned
    /// value may change if system time changes.
    pub time_obtained: u64,

    /// When the temporary authorization is set to expire, in seconds since the Epoch Jan 1, 1970
    /// 0:00 UTC. Note that the PolicyKit daemon is using monotonic time internally so the returned
    /// value may change if system time changes.
    pub time_expires: u64,
}

assert_impl_all!(TemporaryAuthorization: Send, Sync, Unpin);

/// This struct describes identities such as UNIX users and UNIX groups. It is typically used to
/// check if a given process is authorized for an action.
///
/// The following kinds of identities are known:
///
/// * Unix User. `identity_kind` should be set to `unix-user` with key uid (of type uint32).
///
/// * Unix Group. `identity_kind` should be set to `unix-group` with key gid (of type uint32).
///
/// This type only encodes. [`OwnedIdentity`] is its owned counterpart, which decodes as well and
/// has constructors for the kinds polkit documents.
#[derive(Debug, Type, Serialize)]
pub struct Identity<'a> {
    pub identity_kind: &'a str,

    pub identity_details: &'a HashMap<&'a str, Variant<'a>>,
}

assert_impl_all!(Identity<'_>: Send, Sync, Unpin);

/// This struct describes actions registered with the PolicyKit daemon.
#[derive(Debug, Type, Serialize, Deserialize)]
pub struct ActionDescription {
    /// Action Identifier.
    pub action_id: String,

    /// Localized description of the action.
    pub description: String,

    /// Localized message to be displayed when making the user authenticate for an action.
    pub message: String,

    /// Name of the provider of the action or the empty string.
    pub vendor_name: String,

    /// A URL pointing to a place with more information about the action or the empty string.
    pub vendor_url: String,

    /// The themed icon describing the action or the empty string if no icon is set.
    pub icon_name: String,

    /// A value from the ImplicitAuthorization. enumeration for implicit authorizations that apply
    /// to any Subject.
    pub implicit_any: ImplicitAuthorization,

    /// A value from the ImplicitAuthorization. enumeration for implicit authorizations that apply
    /// any Subject in an inactive user session on the local console.
    pub implicit_inactive: ImplicitAuthorization,

    /// A value from the ImplicitAuthorization. enumeration for implicit authorizations that apply
    /// any Subject in an active user session on the local console.
    pub implicit_active: ImplicitAuthorization,

    /// Annotations for the action.
    pub annotations: HashMap<String, String>,
}

assert_impl_all!(ActionDescription: Send, Sync, Unpin);

/// Describes the result of calling `CheckAuthorization()`
#[derive(Debug, Type, Serialize, Deserialize)]
pub struct AuthorizationResult {
    /// TRUE if the given `Subject` is authorized for the given action.
    pub is_authorized: bool,

    /// TRUE if the given `Subject` could be authorized if more information was provided, and
    /// `CheckAuthorizationFlags::ALLOW_USER_INTERACTION` wasn't passed or no suitable
    /// authentication agent was available.
    pub is_challenge: bool,

    /// Details for the result. Known key/value-pairs include `polkit.temporary_authorization_id`
    /// (if the authorization is temporary, this is set to the opaque temporary authorization id),
    /// `polkit.retains_authorization_after_challenge` (Set to a non-empty string if the
    /// authorization will be retained after authentication (if is_challenge is TRUE)),
    /// `polkit.dismissed` (Set to a non-empty string if the authentication dialog was dismissed by
    /// the user).
    pub details: std::collections::HashMap<String, String>,
}

assert_impl_all!(AuthorizationResult: Send, Sync, Unpin);

/// The errors polkit replies with, in the `org.freedesktop.PolicyKit1.Error` domain.
///
/// A call on [`AuthorityProxy`] that the daemon refuses fails with one of these, and an
/// authentication agent replies with one when an authentication does not end in success. A
/// [`zbus::Error`] carrying a method error of this domain converts into the variant of its name;
/// any other error lands in [`Error::ZBus`].
#[derive(Debug, PartialEq, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.PolicyKit1.Error")]
pub enum Error {
    /// A D-Bus error outside the polkit domain.
    #[zbus(error)]
    ZBus(zbus::Error),

    /// The operation failed.
    Failed(String),

    /// The operation was cancelled.
    ///
    /// From an authentication agent, this is how the daemon learns that the user dismissed the
    /// request, which it reports as `polkit.dismissed` in the result the mechanism gets.
    Cancelled(String),

    /// The operation is not supported.
    NotSupported(String),

    /// The caller is not authorized to perform the operation.
    NotAuthorized(String),

    /// The `cancellation_id` passed to `CheckAuthorization()` is already in use by the caller.
    CancellationIdNotUnique(String),
}

/// This D-Bus interface is implemented by the /org/freedesktop/PolicyKit1/Authority object on the
/// well-known name org.freedesktop.PolicyKit1 on the system message bus.
#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
pub trait Authority {
    /// Method for authentication agents to invoke on successful authentication, intended only for
    /// use by a privileged helper process internal to polkit. This method will fail unless a
    /// sufficiently privileged +caller invokes it. Deprecated in favor of
    /// `AuthenticationAgentResponse2()`.
    fn authentication_agent_response(
        &self,
        cookie: &str,
        identity: &Identity<'_>,
    ) -> zbus::Result<()>;

    /// Method for authentication agents to invoke on successful authentication, intended only for
    /// use by a privileged helper process internal to polkit. This method will fail unless a
    /// sufficiently privileged caller invokes it. Note this method was introduced in 0.114 and
    /// should be preferred over `AuthenticationAgentResponse()` as it fixes a security issue.
    fn authentication_agent_response2(
        &self,
        uid: u32,
        cookie: &str,
        identity: &Identity<'_>,
    ) -> zbus::Result<()>;

    /// Cancels an authorization check.
    ///
    /// # Arguments
    ///
    /// * `cancellation_id` - The cancellation_id passed to `CheckAuthorization()`.
    fn cancel_check_authorization(&self, cancellation_id: &str) -> zbus::Result<()>;

    /// Checks if subject is authorized to perform the action with identifier `action_id`
    ///
    /// If `cancellation_id` is non-empty and already in use for the caller, the
    /// `org.freedesktop.PolicyKit1.Error.CancellationIdNotUnique` error is returned.
    ///
    /// Note that `CheckAuthorizationFlags::ALLOW_USER_INTERACTION` SHOULD be passed ONLY if the
    /// event that triggered the authorization check is stemming from an user action, e.g. the
    /// user pressing a button or attaching a device.
    ///
    /// # Arguments
    ///
    /// * `subject` - A Subject struct.
    ///
    /// * `action_id` - Identifier for the action that subject is attempting to do.
    ///
    /// * `details` - Details describing the action. Keys starting with `polkit.` can only be set
    /// if defined in this document.
    ///
    /// Known keys include `polkit.message` and `polkit.gettext_domain` that can be used to override
    /// the message shown to the user. This latter is needed because the user could be running an
    /// authentication agent in another locale than the calling process.
    ///
    /// The (translated version of) `polkit.message` may include references to other keys that are
    /// expanded with their respective values. For example if the key `device_file` has the value
    /// `/dev/sda` then the message "Authenticate to format $(device_file)" is expanded to
    /// "Authenticate to format /dev/sda".
    ///
    /// The key `polkit.icon_name` is used to override the icon shown in the authentication dialog.
    ///
    /// If non-empty, then the request will fail with `org.freedesktop.PolicyKit1.Error.Failed`
    /// unless the process doing the check itself is sufficiently authorized (e.g. running as uid
    /// 0).
    ///
    /// * `flags` - A set of `CheckAuthorizationFlags`.
    ///
    /// * `cancellation_id` - A unique id used to cancel the the authentication check via
    /// `CancelCheckAuthorization()` or the empty string if cancellation is not needed.
    ///
    /// Returns: An `AuthorizationResult` structure.
    fn check_authorization(
        &self,
        subject: &Subject,
        action_id: &str,
        details: &std::collections::HashMap<&str, &str>,
        flags: CheckAuthorizationFlags,
        cancellation_id: &str,
    ) -> zbus::Result<AuthorizationResult>;

    /// Enumerates all registered PolicyKit actions.
    ///
    /// # Arguments:
    ///
    /// * `locale` - The locale to get descriptions in or the blank string to use the system locale.
    fn enumerate_actions(&self, locale: &str) -> zbus::Result<Vec<ActionDescription>>;

    /// Retrieves all temporary authorizations that applies to subject.
    fn enumerate_temporary_authorizations(
        &self,
        subject: &Subject,
    ) -> zbus::Result<Vec<TemporaryAuthorization>>;

    /// Register an authentication agent.
    ///
    /// Note that this should be called by same effective UID which will be passed to
    /// `AuthenticationAgentResponse2()`.
    ///
    /// # Arguments
    ///
    /// * `subject` - The subject to register the authentication agent for, typically a session
    /// subject.
    ///
    /// * `locale` - The locale of the authentication agent.
    ///
    /// * `object_path` - The object path of authentication agent object on the unique name of the
    /// caller.
    fn register_authentication_agent(
        &self,
        subject: &Subject,
        locale: &str,
        object_path: &str,
    ) -> zbus::Result<()>;

    /// Like `RegisterAuthenticationAgent` but takes additional options. If the option fallback (of
    /// type Boolean) is TRUE, then the authentication agent will only be used as a fallback, e.g.
    /// if another agent (without the fallback option set TRUE) is available, it will be used
    /// instead.
    fn register_authentication_agent_with_options(
        &self,
        subject: &Subject,
        locale: &str,
        object_path: &str,
        options: &std::collections::HashMap<&str, Variant<'_>>,
    ) -> zbus::Result<()>;

    /// Revokes all temporary authorizations that applies to `id`.
    fn revoke_temporary_authorization_by_id(&self, id: &str) -> zbus::Result<()>;

    /// Revokes all temporary authorizations that applies to `subject`.
    fn revoke_temporary_authorizations(&self, subject: &Subject) -> zbus::Result<()>;

    /// Unregister an authentication agent.
    ///
    /// # Arguments
    ///
    /// * `subject` - The subject passed to `RegisterAuthenticationAgent()`.
    ///
    /// * `object_path` - The object_path passed to `RegisterAuthenticationAgent()`.
    fn unregister_authentication_agent(
        &self,
        subject: &Subject,
        object_path: &str,
    ) -> zbus::Result<()>;

    /// This signal is emitted when actions and/or authorizations change
    #[zbus(signal)]
    fn changed(&self) -> fdo::Result<()>;

    /// The features supported by the currently used Authority backend.
    ///
    /// This is a flag set, not a single feature: a backend without any of them reports an empty
    /// set, and a newer polkit may report a bit this crate does not name yet, which is retained in
    /// the returned value (see [`AuthorityFeatures::bits`]) instead of being an error.
    #[zbus(property)]
    fn backend_features(&self) -> fdo::Result<AuthorityFeatures>;

    /// The name of the currently used Authority backend.
    #[zbus(property)]
    fn backend_name(&self) -> fdo::Result<String>;

    /// The version of the currently used Authority backend.
    #[zbus(property)]
    fn backend_version(&self) -> fdo::Result<String>;
}

assert_impl_all!(AuthorityProxy<'_>: Send, Sync, Unpin);

/// This D-Bus interface is implemented by an authentication agent, on an object it registers with
/// [`AuthorityProxy::register_authentication_agent`]. The daemon calls it when an authorization
/// check needs the user to authenticate, and is its only caller in practice; this proxy is for a
/// program standing in for the daemon, such as a test of an agent.
#[zbus::proxy(interface = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
pub trait AuthenticationAgent {
    /// Ask the agent to authenticate the user for `action_id`.
    ///
    /// The call returns once the authentication has ended, with an error in the [`Error`] domain
    /// if it did not succeed.
    ///
    /// # Arguments
    ///
    /// * `action_id` - The action the user is authenticating for.
    ///
    /// * `message` - The message to show the user, in the agent's locale.
    ///
    /// * `icon_name` - The name of an icon to show with it, or empty for none.
    ///
    /// * `details` - The details given to `CheckAuthorization()`, plus what the daemon adds.
    ///
    /// * `cookie` - What names this authentication to the daemon.
    ///
    /// * `identities` - Who may authenticate for the action.
    fn begin_authentication(
        &self,
        action_id: &str,
        message: &str,
        icon_name: &str,
        details: &HashMap<&str, &str>,
        cookie: &str,
        identities: &[OwnedIdentity],
    ) -> Result<(), Error>;

    /// Stop the authentication started with `cookie`, if it is still running.
    fn cancel_authentication(&self, cookie: &str) -> Result<(), Error>;
}

assert_impl_all!(AuthenticationAgentProxy<'_>: Send, Sync, Unpin);

// Formats like the `Debug` impl that the `bitflags!` macro generates for a flag set it defines
// itself, e.g. `AuthorityFeatures(TEMPORARY_AUTHORIZATION | 0x2)`, or `AuthorityFeatures(0x0)` for
// the empty set. The macro does not generate it for the `impl` form used above, so that the type
// can carry its own derives.
//
// The macro's flag set is a `#[derive(Debug)]` tuple struct around its internal flags type, so this
// is formatted as a tuple struct too, to match in alternate mode (`{:#?}`) as well as in `{:?}`.
fn debug_flags<F>(name: &str, flags: &F, f: &mut fmt::Formatter<'_>) -> fmt::Result
where
    F: Flags<Bits = u32>,
{
    f.debug_tuple(name).field(&FlagNames(flags)).finish()
}

// The flag names of a flag set, as `bitflags::parser::to_writer` writes them, with unnamed bits in
// hex after them, and `0x0` for the empty set.
struct FlagNames<'a, F>(&'a F);

impl<F> fmt::Debug for FlagNames<'_, F>
where
    F: Flags<Bits = u32>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("0x0")
        } else {
            parser::to_writer(self.0, f)
        }
    }
}

#[cfg(test)]
mod tests {
    use zbus::{
        message::Message,
        wire::{serialized::Context, to_bytes, LE},
        DBusError as _,
    };

    use super::*;

    // Signatures as documented in the polkit D-Bus API reference:
    // https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html
    #[test]
    fn wire_signatures_match_polkit() {
        assert_eq!(<Identity<'_>>::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(
            TemporaryAuthorization::SIGNATURE.to_string(),
            "(ss(sa{sv})tt)"
        );
        assert_eq!(ActionDescription::SIGNATURE.to_string(), "(ssssssuuua{ss})");
        assert_eq!(AuthorizationResult::SIGNATURE.to_string(), "(bba{ss})");

        assert_eq!(CheckAuthorizationFlags::SIGNATURE.to_string(), "u");
        assert_eq!(ImplicitAuthorization::SIGNATURE.to_string(), "u");
        assert_eq!(AuthorityFeatures::SIGNATURE.to_string(), "u");
    }

    #[test]
    fn flags_can_be_dictionary_keys() {
        assert_eq!(
            <HashMap<CheckAuthorizationFlags, u8>>::SIGNATURE.to_string(),
            "a{uy}"
        );
        let flags = CheckAuthorizationFlags::ALLOW_USER_INTERACTION;
        let value = Variant::from(HashMap::from([(flags, 1u8)]));
        let dict = <HashMap<CheckAuthorizationFlags, u8>>::try_from(value).unwrap();
        assert_eq!(dict[&flags], 1);

        assert_eq!(
            <HashMap<AuthorityFeatures, u8>>::SIGNATURE.to_string(),
            "a{uy}"
        );
        let features = AuthorityFeatures::TEMPORARY_AUTHORIZATION;
        let value = Variant::from(HashMap::from([(features, 1u8)]));
        let dict = <HashMap<AuthorityFeatures, u8>>::try_from(value).unwrap();
        assert_eq!(dict[&features], 1);
    }

    // A `Variant` taken out of a received message borrows from the message's buffer.
    #[test]
    fn flags_convert_from_borrowed_values() {
        let ctxt = Context::new(LE, 0);

        let flags = CheckAuthorizationFlags::ALLOW_USER_INTERACTION;
        let encoded = to_bytes(ctxt, &Variant::from(flags)).unwrap();
        let (value, _): (Variant<'_>, _) = encoded.deserialize().unwrap();
        assert_eq!(CheckAuthorizationFlags::try_from(value).unwrap(), flags);

        // Including the bits this crate does not name.
        let features = AuthorityFeatures::from_bits_retain(0b11);
        let encoded = to_bytes(ctxt, &Variant::from(features)).unwrap();
        let (value, _): (Variant<'_>, _) = encoded.deserialize().unwrap();
        assert_eq!(AuthorityFeatures::try_from(value).unwrap(), features);
    }

    #[test]
    fn enums_serialize_as_their_u32_discriminant() {
        let ctxt = Context::new(LE, 0);

        let encoded = to_bytes(ctxt, &ImplicitAuthorization::Authorized).unwrap();
        assert_eq!(encoded.bytes(), 5u32.to_le_bytes());
        let (decoded, _) = encoded.deserialize::<ImplicitAuthorization>().unwrap();
        assert_eq!(decoded, ImplicitAuthorization::Authorized);

        let flags = CheckAuthorizationFlags::ALLOW_USER_INTERACTION;
        let encoded = to_bytes(ctxt, &flags).unwrap();
        assert_eq!(encoded.bytes(), 1u32.to_le_bytes());
        let (decoded, _) = encoded.deserialize::<CheckAuthorizationFlags>().unwrap();
        assert_eq!(decoded, flags);

        let encoded = to_bytes(ctxt, &CheckAuthorizationFlags::empty()).unwrap();
        assert_eq!(encoded.bytes(), 0u32.to_le_bytes());
    }

    #[test]
    fn authority_features_decode_from_their_bits() {
        let ctxt = Context::new(LE, 0);
        let decode = |bits: u32| {
            to_bytes(ctxt, &bits)
                .unwrap()
                .deserialize::<AuthorityFeatures>()
                .map(|(features, _)| features)
        };

        assert_eq!(
            decode(1).unwrap(),
            AuthorityFeatures::TEMPORARY_AUTHORIZATION
        );
        // A backend that supports none of them is not an error.
        assert!(decode(0).unwrap().is_empty());
        // Neither is a bit this crate does not name, e.g. one a newer polkit has added: it is
        // retained, so that it can still be inspected, but is none of the named features.
        let unnamed = decode(0b10).unwrap();
        assert_eq!(unnamed.bits(), 0b10);
        assert!(!unnamed.is_empty());
        assert!(!unnamed.contains(AuthorityFeatures::TEMPORARY_AUTHORIZATION));
        // Known and unnamed bits side by side keep both.
        let both = decode(0b11).unwrap();
        assert!(both.contains(AuthorityFeatures::TEMPORARY_AUTHORIZATION));
        assert_eq!(both.bits(), 0b11);
    }

    // The proxy reads `BackendFeatures` as a property, which goes through `OwnedVariant`.
    #[test]
    fn flags_convert_to_and_from_values() {
        let features = AuthorityFeatures::TEMPORARY_AUTHORIZATION;
        let value = OwnedVariant::try_from(Variant::from(features)).unwrap();
        assert_eq!(value.value_signature().to_string(), "u");
        assert_eq!(AuthorityFeatures::try_from(value).unwrap(), features);

        let value = OwnedVariant::try_from(Variant::from(AuthorityFeatures::empty())).unwrap();
        assert_eq!(
            AuthorityFeatures::try_from(value).unwrap(),
            AuthorityFeatures::empty()
        );

        // Bits that this crate does not name are retained on this path too, rather than being an
        // error, which is what used to happen when a newer polkit reported a feature we don't know.
        let value = OwnedVariant::try_from(Variant::from(0b11u32)).unwrap();
        let features = AuthorityFeatures::try_from(value).unwrap();
        assert_eq!(features.bits(), 0b11);
        assert!(features.contains(AuthorityFeatures::TEMPORARY_AUTHORIZATION));

        let flags = CheckAuthorizationFlags::ALLOW_USER_INTERACTION;
        let value = OwnedVariant::try_from(Variant::from(flags)).unwrap();
        assert_eq!(CheckAuthorizationFlags::try_from(value).unwrap(), flags);
    }

    // `BitFlags<T>` used to be `Default`, so e.g. `Default::default()` could be passed as the flags
    // argument of `check_authorization`. The default is the empty set.
    #[test]
    fn flags_default_to_the_empty_set() {
        assert_eq!(
            CheckAuthorizationFlags::default(),
            CheckAuthorizationFlags::empty()
        );
        assert_eq!(AuthorityFeatures::default(), AuthorityFeatures::empty());
    }

    #[test]
    fn flags_debug_output_names_the_flags() {
        assert_eq!(
            format!("{:?}", CheckAuthorizationFlags::ALLOW_USER_INTERACTION),
            "CheckAuthorizationFlags(ALLOW_USER_INTERACTION)"
        );
        assert_eq!(
            format!("{:?}", CheckAuthorizationFlags::empty()),
            "CheckAuthorizationFlags(0x0)"
        );
        assert_eq!(
            format!("{:?}", AuthorityFeatures::TEMPORARY_AUTHORIZATION),
            "AuthorityFeatures(TEMPORARY_AUTHORIZATION)"
        );
        // Bits without a name are shown in hex after the named ones.
        assert_eq!(
            format!("{:?}", AuthorityFeatures::from_bits_retain(0b11)),
            "AuthorityFeatures(TEMPORARY_AUTHORIZATION | 0x2)"
        );
        assert_eq!(
            format!("{:?}", AuthorityFeatures::from_bits_retain(0b10)),
            "AuthorityFeatures(0x2)"
        );
        // Like the output of the `bitflags!` macro's own, `{:#?}` (which `dbg!` uses) is a
        // multi-line tuple struct.
        assert_eq!(
            format!("{:#?}", AuthorityFeatures::TEMPORARY_AUTHORIZATION),
            "AuthorityFeatures(\n    TEMPORARY_AUTHORIZATION,\n)"
        );
        assert_eq!(
            format!("{:#?}", AuthorityFeatures::empty()),
            "AuthorityFeatures(\n    0x0,\n)"
        );
    }

    // Error names as polkit registers them (polkiterror.c), plus the one the daemon emits on its
    // own for a cancellation id already in use (polkitbackendauthority.c).
    #[test]
    fn errors_are_in_the_polkit_domain() {
        let cases = [
            (Error::Failed("x".into()), "Failed"),
            (Error::Cancelled("x".into()), "Cancelled"),
            (Error::NotSupported("x".into()), "NotSupported"),
            (Error::NotAuthorized("x".into()), "NotAuthorized"),
            (
                Error::CancellationIdNotUnique("x".into()),
                "CancellationIdNotUnique",
            ),
        ];

        for (error, name) in cases {
            assert_eq!(
                error.name().as_str(),
                format!("org.freedesktop.PolicyKit1.Error.{name}")
            );
            assert_eq!(error.description(), Some("x"));
        }
    }

    // A method error of the polkit domain converts into the variant of its name, message included;
    // anything else is kept as it is.
    #[test]
    fn polkit_method_errors_convert_into_their_variant() {
        let call = Message::method_call("/org/example/Object", "Frobnicate")
            .build(&())
            .unwrap();
        let reply = Message::error(&call.header(), "org.freedesktop.PolicyKit1.Error.Cancelled")
            .build(&("dismissed",))
            .unwrap();
        let error = zbus::Error::MethodError(
            "org.freedesktop.PolicyKit1.Error.Cancelled"
                .try_into()
                .unwrap(),
            Some("dismissed".into()),
            reply,
        );

        assert_eq!(Error::from(error), Error::Cancelled("dismissed".into()));
        assert!(matches!(
            Error::from(zbus::Error::MissingField),
            Error::ZBus(zbus::Error::MissingField)
        ));
    }
}
