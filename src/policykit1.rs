use std::collections::HashMap;

use enumflags2::{bitflags, BitFlags};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use static_assertions::assert_impl_all;
use zbus::{fdo, Type, Value};

mod subject;
pub use subject::Subject;

/// Flags used in the CheckAuthorization() method.
#[bitflags]
#[repr(u32)]
#[derive(Type, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum CheckAuthorizationFlags {
    /// If the Subject can obtain the authorization through authentication, and an authentication
    /// agent is available, then attempt to do so. Note, this means that the CheckAuthorization()
    /// method will block while the user is being asked to authenticate.
    AllowUserInteraction = 0x01,
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
#[bitflags]
#[repr(u32)]
#[derive(Type, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum AuthorityFeatures {
    /// The authority supports temporary authorizations that can be obtained through
    /// authentication.
    TemporaryAuthorization = 0x01,
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
#[derive(Debug, Type, Serialize)]
pub struct Identity<'a> {
    pub identity_kind: &'a str,

    pub identity_details: &'a HashMap<&'a str, Value<'a>>,
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
    /// `CheckAuthorizationFlags::AllowUserInteraction` wasn't passed or no suitable authentication
    /// agent was available.
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
    /// Note that `CheckAuthorizationFlags::AllowUserInteraction` SHOULD be passed ONLY if the event
    /// that triggered the authorization check is stemming from an user action, e.g. the user
    /// pressing a button or attaching a device.
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
        flags: BitFlags<CheckAuthorizationFlags>,
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
        options: &std::collections::HashMap<&str, Value<'_>>,
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
    /// set, and a newer polkit may report a bit this crate does not name yet, which is an error
    /// rather than an unnamed variant.
    #[zbus(property)]
    fn backend_features(&self) -> fdo::Result<BitFlags<AuthorityFeatures>>;

    /// The name of the currently used Authority backend.
    #[zbus(property)]
    fn backend_name(&self) -> fdo::Result<String>;

    /// The version of the currently used Authority backend.
    #[zbus(property)]
    fn backend_version(&self) -> fdo::Result<String>;
}

assert_impl_all!(AuthorityProxy<'_>: Send, Sync, Unpin);
#[cfg(feature = "blocking-api")]
assert_impl_all!(AuthorityProxyBlocking<'_>: Send, Sync, Unpin);

#[cfg(test)]
mod tests {
    use zbus::wire::{serialized::Context, to_bytes, LE};

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
        assert_eq!(
            BitFlags::<CheckAuthorizationFlags>::SIGNATURE.to_string(),
            "u"
        );
        assert_eq!(ImplicitAuthorization::SIGNATURE.to_string(), "u");
        assert_eq!(AuthorityFeatures::SIGNATURE.to_string(), "u");
    }

    #[test]
    fn enums_serialize_as_their_u32_discriminant() {
        let ctxt = Context::new(LE, 0);

        let encoded = to_bytes(ctxt, &ImplicitAuthorization::Authorized).unwrap();
        assert_eq!(encoded.bytes(), 5u32.to_le_bytes());
        let (decoded, _) = encoded.deserialize::<ImplicitAuthorization>().unwrap();
        assert_eq!(decoded, ImplicitAuthorization::Authorized);

        let flags: BitFlags<CheckAuthorizationFlags> =
            CheckAuthorizationFlags::AllowUserInteraction.into();
        let encoded = to_bytes(ctxt, &flags).unwrap();
        assert_eq!(encoded.bytes(), 1u32.to_le_bytes());
    }

    #[test]
    fn authority_features_decode_from_their_bits() {
        let ctxt = Context::new(LE, 0);
        let decode = |bits: u32| {
            to_bytes(ctxt, &bits)
                .unwrap()
                .deserialize::<BitFlags<AuthorityFeatures>>()
                .map(|(features, _)| features)
        };

        assert_eq!(
            decode(1).unwrap(),
            AuthorityFeatures::TemporaryAuthorization
        );
        // A backend that supports none of them is not an error.
        assert!(decode(0).unwrap().is_empty());
        // A bit this crate does not name is. The previous `transmute` turned it into an
        // `AuthorityFeatures` that matched no variant.
        assert!(decode(0b10).is_err());
    }
}
