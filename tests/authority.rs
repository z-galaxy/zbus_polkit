//! Drive `AuthorityProxy` against a real `org.freedesktop.PolicyKit1` when one is answering on the
//! system bus, and against an in-process mock of the same interface otherwise.
//!
//! Two environment variables steer the choice:
//!
//! * `ZBUS_POLKIT_MOCK` forces the mock even when a daemon is running.
//! * `ZBUS_POLKIT_REQUIRE_REAL` turns a missing daemon into a failure instead of a silent fallback.
//!
//! CI installs polkit and sets the latter, so the daemon really is what gets exercised there, then
//! runs a second pass with the former for the two assertions this harness cannot make against a
//! daemon: the `uid` type it reads off the wire, which only the mock reports back, and a granted
//! temporary authorization, which a daemon does issue, but only to a session with an authentication
//! agent, and this harness sets up neither.

#![cfg(target_os = "linux")]

mod mock_authority;

use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    process,
    time::Duration,
};

use enumflags2::BitFlags;
use futures_util::StreamExt;
use mock_authority::MockAuthority;
use zbus::{object_server::InterfaceRef, Connection};
use zbus_polkit::policykit1::{AuthorityFeatures, AuthorityProxy, ImplicitAuthorization, Subject};

#[tokio::test]
async fn backend_properties() {
    let harness = Harness::new().await;
    let proxy = harness.proxy().await;

    let name = proxy.backend_name().await.unwrap();
    let version = proxy.backend_version().await.unwrap();
    // Decoding is the assertion here: `BackendFeatures` is a `u` on the wire that has to come back
    // as an `AuthorityFeatures` flag set.
    let features = proxy.backend_features().await.unwrap();

    assert!(!name.is_empty(), "BackendName should not be empty");
    assert!(!version.is_empty(), "BackendVersion should not be empty");

    if harness.kind == Backend::Mock {
        assert_eq!(name, mock_authority::BACKEND_NAME);
        assert_eq!(version, mock_authority::BACKEND_VERSION);
        assert_eq!(features, AuthorityFeatures::TemporaryAuthorization);
    }
}

#[tokio::test]
async fn enumerate_actions() {
    let harness = Harness::new().await;
    let proxy = harness.proxy().await;

    let actions = proxy.enumerate_actions("").await.unwrap();

    // Every entry went through the `(ssssssuuua{ss})` decoder, including its three
    // `ImplicitAuthorization` fields, so a value the enum does not cover fails here.
    assert!(
        !actions.is_empty(),
        "an authority should advertise at least one action"
    );
    assert!(actions.iter().all(|action| !action.action_id.is_empty()));

    if harness.kind == Backend::Mock {
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_id, mock_authority::ACTION_ID);
        assert_eq!(
            actions[0].implicit_any,
            ImplicitAuthorization::NotAuthorized
        );
        assert_eq!(
            actions[0].implicit_inactive,
            ImplicitAuthorization::AuthenticationRequired
        );
        assert_eq!(
            actions[0].implicit_active,
            ImplicitAuthorization::Authorized
        );
    }
}

#[tokio::test]
async fn check_authorization() {
    let harness = Harness::new().await;
    let proxy = harness.proxy().await;
    let subject = Harness::own_process_subject();

    // polkit rejects an action it does not know with `org.freedesktop.PolicyKit1.Error.Failed`, so
    // ask the real daemon about one it just said it has.
    let action_id = match harness.kind {
        Backend::Mock => mock_authority::ACTION_ID.to_string(),
        Backend::Real => {
            let actions = proxy.enumerate_actions("").await.unwrap();

            actions
                .into_iter()
                .next()
                .expect("an authority should advertise at least one action")
                .action_id
        }
    };

    // Without `AllowUserInteraction` polkit answers from the policy alone instead of raising an
    // authentication dialog, so this cannot block the suite.
    let result = proxy
        .check_authorization(&subject, &action_id, &HashMap::new(), BitFlags::empty(), "")
        .await
        .unwrap();

    // The outcome depends on the action and the caller, but polkit never reports both at once: a
    // result is either a decision or a challenge.
    assert!(!(result.is_authorized && result.is_challenge));

    if harness.kind == Backend::Mock {
        assert!(result.is_authorized);
        assert_eq!(
            result
                .details
                .get("polkit.temporary_authorization_id")
                .map(String::as_str),
            Some(mock_authority::TEMPORARY_AUTHORIZATION_ID)
        );

        // The same #101 contract the unit tests lock in, but observed on the wire after a full
        // proxy round-trip: polkit reads `uid` as a signed 32-bit integer and ignores it when it
        // arrives as anything else.
        let mock = harness.mock().await;
        assert_eq!(mock.get().await.last_uid_signature.as_deref(), Some("i"));
    }
}

#[tokio::test]
async fn enumerate_temporary_authorizations() {
    let harness = Harness::new().await;
    let proxy = harness.proxy().await;
    let subject = Harness::own_process_subject();

    match harness.kind {
        Backend::Mock => {
            let auths = proxy
                .enumerate_temporary_authorizations(&subject)
                .await
                .unwrap();

            assert_eq!(auths.len(), 1);
            assert_eq!(auths[0].id, mock_authority::TEMPORARY_AUTHORIZATION_ID);
            assert_eq!(auths[0].action_id, mock_authority::ACTION_ID);
            assert_eq!(auths[0].subject.kind(), "unix-process");
            assert_eq!(auths[0].time_obtained, 1);
            assert_eq!(auths[0].time_expires, 2);
        }
        // polkit only answers this for a `unix-session` subject that the caller is itself in, and a
        // CI runner has no session, so what is reachable against the real daemon is that a
        // `unix-process` subject is refused the documented way. See
        // `polkit_backend_interactive_authority_enumerate_temporary_authorizations()` in
        // polkitbackendinteractiveauthority.c.
        Backend::Real => {
            let err = proxy
                .enumerate_temporary_authorizations(&subject)
                .await
                .unwrap_err();
            let zbus::Error::MethodError(name, _, _) = &err else {
                panic!("expected a D-Bus error reply, got {err:?}");
            };

            assert_eq!(name.as_str(), "org.freedesktop.PolicyKit1.Error.Failed");
        }
    }
}

#[tokio::test]
async fn changed_signal() {
    let harness = Harness::new().await;
    let proxy = harness.proxy().await;

    // Nothing replays `Changed`, so subscribe before provoking it. Subscribing works against both
    // backends: it proves the signal is wired up and, on a bus, that the match rule is accepted.
    let mut stream = proxy.receive_changed().await.unwrap();

    match harness.kind {
        Backend::Mock => {
            let mock = harness.mock().await;
            MockAuthority::changed(mock.signal_emitter()).await.unwrap();

            assert!(
                stream.next().await.is_some(),
                "the mock should emit Changed"
            );
        }
        Backend::Real => {
            let Some(_rule) = TestRule::install() else {
                assert!(
                    env::var(REQUIRE_REAL_ENV).is_err(),
                    "{REQUIRE_REAL_ENV} is set but {POLKIT_RULES_DIR} is not writable, so the \
                     daemon cannot be asked to reload",
                );
                eprintln!(
                    "authority e2e: {POLKIT_RULES_DIR} is not writable, not asking the daemon to \
                     reload"
                );

                return;
            };

            let changed = tokio::time::timeout(RELOAD_TIMEOUT, stream.next()).await;

            assert!(
                matches!(changed, Ok(Some(_))),
                "polkit should emit Changed within {RELOAD_TIMEOUT:?} of a rules file appearing"
            );
        }
    }
}

#[cfg(feature = "blocking-api")]
#[test]
fn blocking_backend_name() {
    // Not a `#[tokio::test]`: the blocking API blocks the calling thread, which panics inside a
    // runtime. Setting the harness up still needs one, and with the `tokio` feature the
    // connections' tasks end up on it, so it has to be multi-threaded to keep driving them while
    // this thread is blocked.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let harness = runtime.block_on(Harness::new());
    let connection = zbus::blocking::Connection::from(harness.client.clone());
    let name = zbus_polkit::policykit1::AuthorityProxyBlocking::new(&connection)
        .unwrap()
        .backend_name()
        .unwrap();

    assert!(!name.is_empty(), "BackendName should not be empty");
    if harness.kind == Backend::Mock {
        assert_eq!(name, mock_authority::BACKEND_NAME);
    }
}

/// Which `org.freedesktop.PolicyKit1.Authority` the tests are talking to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Backend {
    /// The polkit daemon on the system bus.
    Real,
    /// An in-process [`MockAuthority`] on a peer-to-peer connection.
    Mock,
}

/// A connection to an `Authority`, real or mocked.
struct Harness {
    client: Connection,
    /// The mock peer, kept alive for as long as the harness is. `None` for [`Backend::Real`].
    server: Option<Connection>,
    kind: Backend,
}

impl Harness {
    async fn new() -> Self {
        if env::var(MOCK_ENV).is_err() {
            if let Some(client) = system_authority().await {
                eprintln!("authority e2e: using the real org.freedesktop.PolicyKit1");

                return Self {
                    client,
                    server: None,
                    kind: Backend::Real,
                };
            }

            assert!(
                env::var(REQUIRE_REAL_ENV).is_err(),
                "{REQUIRE_REAL_ENV} is set but nothing answered as \
                 org.freedesktop.PolicyKit1 on the system bus",
            );
            eprintln!("authority e2e: no polkit on the system bus, falling back to the mock");
        } else {
            eprintln!("authority e2e: {MOCK_ENV} is set, using the mock");
        }

        let (server, client) = mock_authority::connect().await;

        Self {
            client,
            server: Some(server),
            kind: Backend::Mock,
        }
    }

    async fn proxy(&self) -> AuthorityProxy<'_> {
        // `AuthorityProxy` addresses `org.freedesktop.PolicyKit1` by default. There is no bus to
        // resolve that name on a peer-to-peer connection, but zbus routes an incoming call by
        // object path and interface alone, so the mock is reached regardless of the destination.
        AuthorityProxy::new(&self.client).await.unwrap()
    }

    /// A `unix-process` subject for the test process itself.
    fn own_process_subject() -> Subject {
        Subject::new_for_pid(process::id(), None, None).unwrap()
    }

    /// The mock's interface handle, for asserting on what it received and emitting from it.
    async fn mock(&self) -> InterfaceRef<MockAuthority> {
        let server = self
            .server
            .as_ref()
            .expect("only the mock backend has a server");

        mock_authority::interface(server).await
    }
}

/// A system-bus connection, if `org.freedesktop.PolicyKit1` is there and answering.
async fn system_authority() -> Option<Connection> {
    let connection = Connection::system().await.ok()?;
    // A proxy can be built for a name nobody owns, so read a property to prove the daemon is up.
    AuthorityProxy::new(&connection)
        .await
        .ok()?
        .backend_name()
        .await
        .ok()?;

    Some(connection)
}

/// A rules file that makes the daemon reload, removed again on drop.
///
/// polkit watches its rules directories and reloads every rule when a `.rules` file appears,
/// changes or goes away, and it emits `Changed` once it is done. See
/// `polkit_backend_common_on_dir_monitor_changed()` and
/// `polkit_backend_common_reload_scripts()` in polkitbackendcommon.c.
struct TestRule(PathBuf);

impl TestRule {
    /// `None` if the rules directory cannot be written to, which is the normal case for a test
    /// process. CI hands the directory to the user the tests run as.
    fn install() -> Option<Self> {
        let path =
            Path::new(POLKIT_RULES_DIR).join(format!("99-zbus-polkit-{}.rules", process::id()));
        // A comment is a complete script, so the daemon reloads without any of its answers
        // changing.
        fs::write(&path, "// Installed by the zbus_polkit Authority tests.\n").ok()?;

        Some(Self(path))
    }
}

impl Drop for TestRule {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

const MOCK_ENV: &str = "ZBUS_POLKIT_MOCK";
const REQUIRE_REAL_ENV: &str = "ZBUS_POLKIT_REQUIRE_REAL";
const POLKIT_RULES_DIR: &str = "/etc/polkit-1/rules.d";
/// Generous: the daemon has to notice the new file, re-execute every rule and answer the
/// subscription, all on a machine that is busy running the rest of the suite.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);
