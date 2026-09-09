use std::{collections::HashMap, os::fd::AsFd};

use enumflags2::{bitflags, BitFlags};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use static_assertions::assert_impl_all;
use zbus::{
    fdo,
    names::OwnedUniqueName,
    zvariant::{Fd, OwnedValue, Type, Value},
};

use crate::Error;

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

impl TryFrom<OwnedValue> for AuthorityFeatures {
    type Error = <u32 as TryFrom<OwnedValue>>::Error;

    fn try_from(v: OwnedValue) -> Result<Self, Self::Error> {
        // safe because AuthorityFeatures has repr u32
        Ok(unsafe { std::mem::transmute::<u32, AuthorityFeatures>(v.try_into()?) })
    }
}

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

/// This struct describes subjects such as UNIX processes. It is typically used to check if a given
/// process is authorized for an action.
///
/// The following kinds of subjects are known:
///
/// * Unix Process. `subject_kind` should be set to `unix-process` with keys `pidfd` (of type `fd`)
///   and `uid` (of type `int32`) when the kernel supports pidfds, or alternatively with keys `pid`
///   (of type `uint32`), `uid` (of type `int32`) and `start-time` (of type `uint64`).
///
/// * Unix Session. `subject_kind` should be set to `unix-session` with the key `session-id` (of
///   type `string`).
///
/// * System Bus Name. `subject_kind` should be set to `system-bus-name` with the key `name` (of
///   type `string`).
#[derive(Debug, Type, Serialize, Deserialize)]
pub struct Subject {
    /// The type of the subject.
    pub subject_kind: String,

    /// Details about the subject. Depending of the value of `subject_kind`, a set of well-defined
    /// key/value pairs are guaranteed to be available.
    pub subject_details: HashMap<String, OwnedValue>,
}

assert_impl_all!(Subject: Send, Sync, Unpin);

impl Subject {
    /// Create a `Subject` for a process identified by `pidfd`.
    ///
    /// A pidfd names a specific process incarnation, so this is not subject to the PID-reuse
    /// race that [`new_for_pid`](Self::new_for_pid) is. Polkit requires `uid` to be sent
    /// together with a pidfd and will not look it up itself; obtain both from a trusted source
    /// at the same time (e.g. `SO_PEERPIDFD` and `SO_PEERCRED`, or `pidfd_open` and a known
    /// uid).
    ///
    /// # Arguments
    ///
    /// * `pidfd` - A pidfd for the process (from `pidfd_open(2)` or `SO_PEERPIDFD`)
    ///
    /// * `uid` - The (real, not effective) uid of the owner of the process
    pub fn new_for_owner(pidfd: impl AsFd, uid: u32) -> Result<Self, Error> {
        let fd = Fd::from(pidfd.as_fd().try_clone_to_owned()?);
        let mut hashmap = HashMap::new();
        hashmap.insert(
            "pidfd".to_string(),
            OwnedValue::try_from(Value::from(fd)).map_err(|e| {
                std::io::Error::other(format!("failed to store pidfd in a D-Bus value: {e}"))
            })?,
        );
        hashmap.insert("uid".to_string(), (uid as i32).into());

        Ok(Self {
            subject_kind: "unix-process".into(),
            subject_details: hashmap,
        })
    }

    /// Create a `Subject` for `pid`, `start_time` & `uid`.
    ///
    /// A PID can be reused after the original process exits, so this form is racy. Prefer
    /// [`new_for_owner`](Self::new_for_owner) when the kernel and polkit support pidfds.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process ID
    ///
    /// * `start_time` - The start time for `pid` or `None` to look it up in e.g. `/proc`
    ///
    /// * `uid` - The (real, not effective) uid of the owner of `pid` or `None` to look it up in
    ///   e.g. `/proc`
    pub fn new_for_pid(pid: u32, start_time: Option<u64>, uid: Option<u32>) -> Result<Self, Error> {
        let start_time = match start_time {
            Some(s) => s,
            None => pid_start_time(pid)?,
        };
        let uid = match uid {
            Some(u) => u,
            None => pid_uid_racy(pid)?,
        };
        let mut hashmap = HashMap::new();
        hashmap.insert("pid".to_string(), pid.into());
        hashmap.insert("start-time".to_string(), start_time.into());
        hashmap.insert("uid".to_string(), (uid as i32).into());

        Ok(Self {
            subject_kind: "unix-process".into(),
            subject_details: hashmap,
        })
    }

    /// Create a `Subject` for a message for querying if the sender of a Message is permitted to
    /// execute an action.
    ///
    /// # Arguments
    ///
    /// * `message_header` - The header of the message which caused an authentication to be
    ///   necessary.
    pub fn new_for_message_header(
        message_header: &zbus::message::Header<'_>,
    ) -> Result<Self, Error> {
        let mut subject_details = HashMap::new();
        match message_header.sender() {
            Some(sender) => {
                subject_details.insert(
                    "name".to_string(),
                    OwnedUniqueName::from(sender.clone()).try_into().unwrap(),
                );
            }
            None => {
                return Err(Error::MissingSender);
            }
        }

        Ok(Self {
            subject_kind: "system-bus-name".to_string(),
            subject_details,
        })
    }
}

fn pid_start_time(pid: u32) -> Result<u64, Error> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_start_time(&stat)
}

// Extract the process start time (field 22 of proc(5) `stat`, in clock ticks since boot).
//
// The second field, `comm`, is the executable name wrapped in parentheses and may itself contain
// spaces and parentheses, so fields are counted from the *last* closing parenthesis rather than
// from the start of the line.
fn parse_start_time(stat: &str) -> Result<u64, Error> {
    let start_time = stat
        .rfind(')')
        .and_then(|i| stat[i..].split(' ').nth(20))
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;

    Ok(start_time.parse()?)
}

// Return the "current" UID.  Note that this is inherently racy, and the value may already be
// obsolete by the time this function returns; this function only guarantees that the UID was valid
// at some point during its execution.
fn pid_uid_racy(pid: u32) -> Result<u32, Error> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    parse_uid(&status)
}

// Extract the real UID from the contents of proc(5) `status`.
//
// The `Uid:` line lists the real, effective, saved set and filesystem UIDs; only the first one is
// returned, since that is what polkit expects in a `unix-process` subject.
fn parse_uid(status: &str) -> Result<u32, Error> {
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().next())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;

    Ok(uid.parse()?)
}

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
#[cfg(feature = "blocking-api")]
assert_impl_all!(AuthorityProxyBlocking<'_>: Send, Sync, Unpin);

#[cfg(test)]
mod tests {
    use zbus::{
        message::Message,
        zvariant::{serialized::Context, to_bytes, LE},
    };

    use super::*;

    #[cfg(target_os = "linux")]
    fn pidfd_for_self() -> rustix::fd::OwnedFd {
        rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(std::process::id() as i32).expect("nonzero pid"),
            rustix::process::PidfdFlags::empty(),
        )
        .expect("pidfd_open of self")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subject_for_owner_sends_pidfd_and_uid() {
        let pidfd = pidfd_for_self();
        let subject = Subject::new_for_owner(&pidfd, 1234).unwrap();

        assert_eq!(subject.subject_kind, "unix-process");
        assert_eq!(subject.subject_details.len(), 2);
        // A UNIX_FD ('h'), not a raw i32: polkit looks the handle up in the message's fd
        // list. Sent as any other type it is ignored and polkit falls back to pid+start-time.
        assert_eq!(
            subject.subject_details["pidfd"]
                .value_signature()
                .to_string(),
            "h"
        );
        assert!(!subject.subject_details.contains_key("pid"));
        assert!(!subject.subject_details.contains_key("start-time"));
        // polkit refuses a pidfd subject without a uid, and ignores a uid that is not i32.
        assert_eq!(*subject.subject_details["uid"], Value::I32(1234));
    }

    #[test]
    fn subject_for_pid_uses_polkit_wire_types() {
        let subject = Subject::new_for_pid(4242, Some(1_000_000), Some(1234)).unwrap();

        assert_eq!(subject.subject_kind, "unix-process");
        assert_eq!(subject.subject_details.len(), 3);
        assert_eq!(*subject.subject_details["pid"], Value::U32(4242));
        assert_eq!(
            *subject.subject_details["start-time"],
            Value::U64(1_000_000)
        );
        // polkit reads `uid` as a signed 32-bit integer. Sent as any other type it is silently
        // ignored and polkit falls back to its own racy /proc lookup, which defeats the purpose
        // of passing a UID obtained from a trusted source (see #101).
        assert_eq!(*subject.subject_details["uid"], Value::I32(1234));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subject_for_pid_looks_up_the_process_in_proc() {
        use std::os::unix::fs::MetadataExt;

        let pid = std::process::id();
        let subject = Subject::new_for_pid(pid, None, None).unwrap();

        // /proc/<pid> is owned by the process's UID, which gives us an independent source of
        // truth that doesn't go through the parser under test.
        let uid = std::fs::metadata("/proc/self").unwrap().uid();
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let start_time = parse_start_time(&stat).unwrap();

        assert_eq!(*subject.subject_details["pid"], Value::U32(pid));
        assert_eq!(*subject.subject_details["uid"], Value::I32(uid as i32));
        assert_eq!(
            *subject.subject_details["start-time"],
            Value::U64(start_time)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subject_for_pid_fails_for_a_missing_process() {
        // pid_max is capped at 2^22 on Linux, so this PID can never exist.
        let err = Subject::new_for_pid(u32::MAX, None, None).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err:?}");
    }

    #[test]
    fn start_time_is_field_22_counted_from_the_last_paren() {
        // proc(5): pid, (comm), state, ppid, pgrp, session, tty_nr, tpgid, flags, minflt,
        // cminflt, majflt, cmajflt, utime, stime, cutime, cstime, priority, nice, num_threads,
        // itrealvalue, starttime, vsize, rss, ...
        let stat = "1 (systemd) S 0 1 1 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 42 12345678 100\n";
        assert_eq!(parse_start_time(stat).unwrap(), 42);

        // `comm` is not escaped, so a process name containing spaces and parentheses shifts
        // every naive field count. Counting from the last `)` is what makes this work.
        let stat = "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 \
                    0 987654 12345678 100\n";
        assert_eq!(parse_start_time(stat).unwrap(), 987654);
    }

    #[test]
    fn start_time_rejects_malformed_stat() {
        assert!(matches!(parse_start_time(""), Err(Error::Io(_))));
        assert!(matches!(
            parse_start_time("no parens here"),
            Err(Error::Io(_))
        ));
        // Too few fields after `comm`.
        assert!(matches!(
            parse_start_time("1234 (x) S 1 1234"),
            Err(Error::Io(_))
        ));
        // Field 22 present but not a number.
        let stat = "1 (x) S 0 1 1 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 forty-two 12345678 100";
        assert!(matches!(parse_start_time(stat), Err(Error::ParseInt(_))));
    }

    #[test]
    fn uid_is_the_real_uid_from_status() {
        let status = "Name:\tmy proc\n\
                      Umask:\t0022\n\
                      State:\tS (sleeping)\n\
                      Tgid:\t1234\n\
                      Pid:\t1234\n\
                      PPid:\t1\n\
                      TracerPid:\t0\n\
                      Uid:\t1000\t1001\t1002\t1003\n\
                      Gid:\t2000\t2001\t2002\t2003\n";
        // Real UID, not effective (1001) or saved-set (1002).
        assert_eq!(parse_uid(status).unwrap(), 1000);
    }

    #[test]
    fn uid_rejects_malformed_status() {
        assert!(matches!(parse_uid(""), Err(Error::Io(_))));
        assert!(matches!(
            parse_uid("Name:\tx\nGid:\t0\t0\t0\t0\n"),
            Err(Error::Io(_))
        ));
        assert!(matches!(parse_uid("Uid:\n"), Err(Error::Io(_))));
        assert!(matches!(
            parse_uid("Uid:\tnobody\n"),
            Err(Error::ParseInt(_))
        ));
    }

    // Signatures as documented in the polkit D-Bus API reference:
    // https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html
    #[test]
    fn wire_signatures_match_polkit() {
        assert_eq!(Subject::SIGNATURE.to_string(), "(sa{sv})");
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
        let ctxt = Context::new_dbus(LE, 0);

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
    fn authority_features_from_value() {
        let features = AuthorityFeatures::try_from(OwnedValue::from(1u32)).unwrap();
        assert_eq!(features, AuthorityFeatures::TemporaryAuthorization);

        let not_a_u32 = OwnedValue::try_from(Value::Str("nope".into())).unwrap();
        assert!(AuthorityFeatures::try_from(not_a_u32).is_err());
    }

    #[test]
    fn subject_for_message_header_uses_the_sender_bus_name() {
        let msg = Message::method_call("/org/example/Object", "Frobnicate")
            .unwrap()
            .sender(":1.42")
            .unwrap()
            .build(&())
            .unwrap();

        let subject = Subject::new_for_message_header(&msg.header()).unwrap();

        assert_eq!(subject.subject_kind, "system-bus-name");
        assert_eq!(subject.subject_details.len(), 1);
        assert_eq!(*subject.subject_details["name"], Value::Str(":1.42".into()));
    }

    #[test]
    fn subject_for_message_header_requires_a_sender() {
        let msg = Message::method_call("/org/example/Object", "Frobnicate")
            .unwrap()
            .build(&())
            .unwrap();

        let err = Subject::new_for_message_header(&msg.header()).unwrap_err();
        assert!(matches!(err, Error::MissingSender), "{err:?}");
    }
}
