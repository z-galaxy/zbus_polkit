//! An in-process stand-in for the polkit daemon.
//!
//! It implements enough of `org.freedesktop.PolicyKit1.Authority` to drive `AuthorityProxy` over a
//! peer-to-peer connection, and answers with fixed values the tests can assert on.

use std::collections::HashMap;

use enumflags2::BitFlags;
use futures_util::future;
use zbus::{
    connection,
    object_server::{InterfaceRef, SignalEmitter},
    Connection, Guid, OwnedValue,
};
use zbus_polkit::policykit1::{
    ActionDescription, AuthorityFeatures, AuthorizationResult, CheckAuthorizationFlags,
    ImplicitAuthorization, Subject, TemporaryAuthorization,
};

/// Serve a [`MockAuthority`] on one end of a socket pair and hand back both ends, server first.
///
/// The server has to outlive the client for the client to have anything to talk to.
pub async fn connect() -> (Connection, Connection) {
    // `Builder::unix_stream` takes a std stream and drives it on whichever runtime the connection
    // is built on, so the same pair works for both the async-io and tokio builds.
    let (server_stream, client_stream) = std::os::unix::net::UnixStream::pair().unwrap();
    let (server, client) = (
        connection::Builder::unix_stream(server_stream),
        connection::Builder::unix_stream(client_stream),
    );

    let server = server
        .server(Guid::generate())
        .p2p()
        .serve_at(AUTHORITY_PATH, MockAuthority::default())
        .build();

    // Both ends have to make progress for the peer-to-peer handshake to finish.
    future::try_join(server, client.p2p().build())
        .await
        .expect("p2p handshake")
}

/// The mock's interface handle, for asserting on what it received and emitting from it.
pub async fn interface(server: &Connection) -> InterfaceRef<MockAuthority> {
    server
        .object_server()
        .interface(AUTHORITY_PATH)
        .await
        .expect("the mock is served at the Authority path")
}

#[derive(Default)]
pub struct MockAuthority {
    /// Signature of the `uid` value in the last subject passed to `CheckAuthorization`.
    pub last_uid_signature: Option<String>,
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl MockAuthority {
    // Takes the subject in the form it arrives in rather than as a `Subject`, so that what is
    // asserted is what the encoder put on the wire and not what this crate's own decoder made of
    // it afterwards.
    async fn check_authorization(
        &mut self,
        subject: (String, HashMap<String, OwnedValue>),
        _action_id: String,
        _details: HashMap<String, String>,
        _flags: BitFlags<CheckAuthorizationFlags>,
        _cancellation_id: String,
    ) -> AuthorizationResult {
        let (_kind, details) = subject;
        self.last_uid_signature = details
            .get("uid")
            .map(|uid| uid.value_signature().to_string());

        AuthorizationResult {
            is_authorized: true,
            is_challenge: false,
            details: HashMap::from([(
                "polkit.temporary_authorization_id".into(),
                TEMPORARY_AUTHORIZATION_ID.into(),
            )]),
        }
    }

    async fn enumerate_actions(&self, _locale: String) -> Vec<ActionDescription> {
        vec![ActionDescription {
            action_id: ACTION_ID.into(),
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
            id: TEMPORARY_AUTHORIZATION_ID.into(),
            action_id: ACTION_ID.into(),
            subject,
            time_obtained: 1,
            time_expires: 2,
        }]
    }

    async fn cancel_check_authorization(&self, _cancellation_id: String) {}

    async fn revoke_temporary_authorization_by_id(&self, _id: String) {}

    async fn revoke_temporary_authorizations(&self, _subject: Subject) {}

    #[zbus(signal)]
    pub async fn changed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(property)]
    fn backend_features(&self) -> u32 {
        AuthorityFeatures::TemporaryAuthorization as u32
    }

    #[zbus(property)]
    fn backend_name(&self) -> String {
        BACKEND_NAME.into()
    }

    #[zbus(property)]
    fn backend_version(&self) -> String {
        BACKEND_VERSION.into()
    }
}

pub const BACKEND_NAME: &str = "zbus-polkit-mock";
pub const BACKEND_VERSION: &str = "0";
pub const ACTION_ID: &str = "org.zbus.BeAwesome";
pub const TEMPORARY_AUTHORIZATION_ID: &str = "mock-auth";

const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
