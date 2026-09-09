//! Drive `AuthorityProxy` against a real `org.freedesktop.PolicyKit1` when one is answering on the
//! system bus, and against an in-process mock of the same interface otherwise.
//!
//! Two environment variables steer the choice:
//!
//! * `ZBUS_POLKIT_MOCK` forces the mock even when a daemon is running.
//! * `ZBUS_POLKIT_REQUIRE_REAL` turns a missing daemon into a failure instead of a silent fallback.
//!
//! CI installs polkit and sets the latter, so the daemon really is what gets exercised there, then
//! runs a second pass with the former for the assertions only a mock can make: the `uid` type on
//! the wire and the `Changed` signal.

#![cfg(target_os = "linux")]

use std::{collections::HashMap, env};

use enumflags2::BitFlags;
use futures_util::{future, StreamExt};
use zbus::{
    connection,
    object_server::{InterfaceRef, SignalEmitter},
    Connection, Guid,
};
use zbus_polkit::policykit1::{
    ActionDescription, AuthorityFeatures, AuthorityProxy, AuthorizationResult,
    CheckAuthorizationFlags, ImplicitAuthorization, Subject, TemporaryAuthorization,
};

#[test]
fn backend_properties() {
    zbus::block_on(async {
        let harness = Harness::new().await;
        let proxy = harness.proxy().await;

        let name = proxy.backend_name().await.unwrap();
        let version = proxy.backend_version().await.unwrap();
        // Decoding is the assertion here: `BackendFeatures` is a `u` on the wire that has to come
        // back as an `AuthorityFeatures` flag set.
        let features = proxy.backend_features().await.unwrap();

        assert!(!name.is_empty(), "BackendName should not be empty");
        assert!(!version.is_empty(), "BackendVersion should not be empty");

        if harness.kind == Backend::Mock {
            assert_eq!(name, MOCK_BACKEND_NAME);
            assert_eq!(version, MOCK_BACKEND_VERSION);
            assert_eq!(features, AuthorityFeatures::TemporaryAuthorization);
        }
    });
}

#[test]
fn enumerate_actions() {
    zbus::block_on(async {
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
            assert_eq!(actions[0].action_id, MOCK_ACTION_ID);
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
    });
}

#[test]
fn check_authorization() {
    zbus::block_on(async {
        let harness = Harness::new().await;
        let proxy = harness.proxy().await;
        let subject = Harness::own_process_subject();

        // polkit rejects an action it does not know with
        // `org.freedesktop.PolicyKit1.Error.Failed`, so ask the real daemon about one it just said
        // it has.
        let action_id = match harness.kind {
            Backend::Mock => MOCK_ACTION_ID.to_string(),
            Backend::Real => {
                let actions = proxy.enumerate_actions("").await.unwrap();

                actions
                    .into_iter()
                    .next()
                    .expect("an authority should advertise at least one action")
                    .action_id
            }
        };

        // Without `AllowUserInteraction` polkit answers from the policy alone instead of raising
        // an authentication dialog, so this cannot block the suite.
        let result = proxy
            .check_authorization(&subject, &action_id, &HashMap::new(), BitFlags::empty(), "")
            .await
            .unwrap();

        // The outcome depends on the action and the caller, but polkit never reports both at once:
        // a result is either a decision or a challenge.
        assert!(!(result.is_authorized && result.is_challenge));

        if harness.kind == Backend::Mock {
            assert!(result.is_authorized);
            assert_eq!(
                result
                    .details
                    .get("polkit.temporary_authorization_id")
                    .map(String::as_str),
                Some("mock-auth")
            );

            // The same #101 contract the unit tests lock in, but observed on the wire after a full
            // proxy round-trip: polkit reads `uid` as a signed 32-bit integer and ignores it when
            // it arrives as anything else.
            let mock = harness.mock().await;
            assert_eq!(mock.get().await.last_uid_signature.as_deref(), Some("i"));
        }
    });
}

#[test]
fn enumerate_temporary_authorizations() {
    zbus::block_on(async {
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
                assert_eq!(auths[0].id, "mock-auth");
                assert_eq!(auths[0].action_id, MOCK_ACTION_ID);
                assert_eq!(auths[0].subject.subject_kind, "unix-process");
                assert_eq!(auths[0].time_obtained, 1);
                assert_eq!(auths[0].time_expires, 2);
            }
            // polkit only answers this for a `unix-session` subject that the caller is itself in,
            // and a CI runner has no session, so what is reachable against the real daemon is that
            // a `unix-process` subject is refused the documented way. See
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
    });
}

#[test]
fn changed_signal() {
    zbus::block_on(async {
        let harness = Harness::new().await;
        let proxy = harness.proxy().await;

        // Subscribing works against both backends: it proves the signal is wired up and, on a bus,
        // that the match rule is accepted.
        let mut stream = proxy.receive_changed().await.unwrap();

        // Only the mock can be made to emit on demand. The real daemon emits `Changed` when its
        // actions or authorizations change, which a test has no business provoking.
        if harness.kind == Backend::Mock {
            let mock = harness.mock().await;
            MockAuthority::changed(mock.signal_emitter()).await.unwrap();

            assert!(stream.next().await.is_some(), "mock should emit Changed");
        }
    });
}

#[cfg(feature = "blocking-api")]
#[test]
fn blocking_backend_name() {
    // Deliberately not inside `block_on`: under tokio the blocking API would start a nested
    // runtime.
    let harness = zbus::block_on(Harness::new());
    let connection = zbus::blocking::Connection::from(harness.client.clone());
    let name = zbus_polkit::policykit1::AuthorityProxyBlocking::new(&connection)
        .unwrap()
        .backend_name()
        .unwrap();

    assert!(!name.is_empty(), "BackendName should not be empty");
    if harness.kind == Backend::Mock {
        assert_eq!(name, MOCK_BACKEND_NAME);
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

        #[cfg(not(feature = "tokio"))]
        let (server_stream, client_stream) = std::os::unix::net::UnixStream::pair().unwrap();
        #[cfg(feature = "tokio")]
        let (server_stream, client_stream) = tokio::net::UnixStream::pair().unwrap();

        #[cfg(not(feature = "tokio"))]
        let (server, client) = (
            connection::Builder::async_io_unix_stream(server_stream),
            connection::Builder::async_io_unix_stream(client_stream),
        );
        #[cfg(feature = "tokio")]
        let (server, client) = (
            connection::Builder::unix_stream(server_stream),
            connection::Builder::unix_stream(client_stream),
        );

        let server = server
            .server(Guid::generate())
            .unwrap()
            .p2p()
            .serve_at(AUTHORITY_PATH, MockAuthority::default())
            .unwrap()
            .build();

        // Both ends have to make progress for the peer-to-peer handshake to finish.
        let (server, client) = future::try_join(server, client.p2p().build())
            .await
            .expect("p2p handshake");

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
        Subject::new_for_owner(std::process::id(), None, None).unwrap()
    }

    /// The mock's interface handle, for asserting on what it received and emitting from it.
    async fn mock(&self) -> InterfaceRef<MockAuthority> {
        self.server
            .as_ref()
            .expect("only the mock backend has a server")
            .object_server()
            .interface(AUTHORITY_PATH)
            .await
            .unwrap()
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

/// Enough of `org.freedesktop.PolicyKit1.Authority` to drive `AuthorityProxy` without a daemon.
#[derive(Default)]
struct MockAuthority {
    /// Signature of the `uid` value in the last subject passed to `CheckAuthorization`.
    last_uid_signature: Option<String>,
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl MockAuthority {
    async fn check_authorization(
        &mut self,
        subject: Subject,
        _action_id: String,
        _details: HashMap<String, String>,
        _flags: BitFlags<CheckAuthorizationFlags>,
        _cancellation_id: String,
    ) -> AuthorizationResult {
        self.last_uid_signature = subject
            .subject_details
            .get("uid")
            .map(|uid| uid.value_signature().to_string());

        AuthorizationResult {
            is_authorized: true,
            is_challenge: false,
            details: HashMap::from([(
                "polkit.temporary_authorization_id".into(),
                "mock-auth".into(),
            )]),
        }
    }

    async fn enumerate_actions(&self, _locale: String) -> Vec<ActionDescription> {
        vec![ActionDescription {
            action_id: MOCK_ACTION_ID.into(),
            description: "Be awesome".into(),
            message: "Authentication is required to be awesome".into(),
            vendor_name: "zbus".into(),
            vendor_url: String::new(),
            icon_name: String::new(),
            implicit_any: ImplicitAuthorization::NotAuthorized,
            implicit_inactive: ImplicitAuthorization::AuthenticationRequired,
            implicit_active: ImplicitAuthorization::Authorized,
            annotations: HashMap::new(),
        }]
    }

    async fn enumerate_temporary_authorizations(
        &self,
        subject: Subject,
    ) -> Vec<TemporaryAuthorization> {
        vec![TemporaryAuthorization {
            id: "mock-auth".into(),
            action_id: MOCK_ACTION_ID.into(),
            subject,
            time_obtained: 1,
            time_expires: 2,
        }]
    }

    async fn cancel_check_authorization(&self, _cancellation_id: String) {}

    async fn revoke_temporary_authorization_by_id(&self, _id: String) {}

    async fn revoke_temporary_authorizations(&self, _subject: Subject) {}

    #[zbus(signal)]
    async fn changed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(property)]
    fn backend_features(&self) -> u32 {
        AuthorityFeatures::TemporaryAuthorization as u32
    }

    #[zbus(property)]
    fn backend_name(&self) -> String {
        MOCK_BACKEND_NAME.into()
    }

    #[zbus(property)]
    fn backend_version(&self) -> String {
        MOCK_BACKEND_VERSION.into()
    }
}

const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const MOCK_ENV: &str = "ZBUS_POLKIT_MOCK";
const REQUIRE_REAL_ENV: &str = "ZBUS_POLKIT_REQUIRE_REAL";
const MOCK_BACKEND_NAME: &str = "zbus-polkit-mock";
const MOCK_BACKEND_VERSION: &str = "0";
const MOCK_ACTION_ID: &str = "org.zbus.BeAwesome";
