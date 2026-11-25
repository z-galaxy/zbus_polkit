//! Serve `org.freedesktop.PolicyKit1.Authority` with this crate's types, as a polkit
//! implementation would, and call it through `AuthorityProxy`: what the proxy sends has to arrive
//! as the types it was sent as, and what the service replies, borrowing it from what it keeps, has
//! to come back as it was sent.

#![cfg(unix)]

use std::{collections::HashMap, fs::File};

use futures_util::future;
use zbus::{
    connection, fdo,
    message::Message,
    object_server::{Interface, InterfaceRef},
    Connection, Guid, OwnedVariant, Variant,
};
use zbus_polkit::policykit1::{
    ActionDescription, AuthorityFeatures, AuthorityProxy, AuthorizationResult,
    CheckAuthorizationFlags, Error, Identity, ImplicitAuthorization, Subject,
    TemporaryAuthorization,
};

#[tokio::test]
async fn a_check_arrives_as_it_was_sent() {
    let harness = Harness::new().await;
    let proxy = harness.proxy().await;
    let pidfd = File::open("/dev/null").unwrap();
    let details = HashMap::from([("polkit.message", "Authenticate to be awesome")]);

    let result = proxy
        .check_authorization(
            &Subject::new_for_owner(&pidfd, 1000),
            ACTION_ID,
            &details,
            CheckAuthorizationFlags::ALLOW_USER_INTERACTION,
            "",
        )
        .await
        .unwrap();
    assert_eq!(result, authorized());

    let caller = Message::method_call("/org/example/Object", "Frobnicate")
        .sender(":1.42")
        .build(&())
        .unwrap();
    let subject = Subject::new_for_message_header(&caller.header()).unwrap();
    proxy
        .check_authorization(
            &subject,
            ACTION_ID,
            &HashMap::new(),
            CheckAuthorizationFlags::empty(),
            "",
        )
        .await
        .unwrap();

    let authority = harness.authority().await;
    let authority = authority.get().await;
    let [process, bus_name] = &authority.subjects[..] else {
        panic!("expected two subjects, got {:?}", authority.subjects);
    };
    assert_eq!(process.kind(), "unix-process");
    assert!(process.pidfd().is_some());
    assert_eq!(process.uid(), Some(1000));
    assert_eq!(bus_name.bus_name().map(|name| name.as_str()), Some(":1.42"));
    assert_eq!(
        authority.checks,
        [
            (
                HashMap::from([("polkit.message".into(), "Authenticate to be awesome".into())]),
                CheckAuthorizationFlags::ALLOW_USER_INTERACTION,
            ),
            (HashMap::new(), CheckAuthorizationFlags::empty()),
        ]
    );
}

// A mechanism asks the authority in a method of its own before it acts. When that method returns
// this crate's `Error`, or a `zbus::fdo::Result`, `?` takes the authority's error into it, and the
// mechanism's own caller gets the error under polkit's name.
#[tokio::test]
async fn an_error_of_the_authority_reaches_a_mechanisms_caller_in_the_polkit_domain() {
    let harness = Harness::new().await;
    let authority = AuthorityProxy::new(&harness.client).await.unwrap();
    let (_mechanism, caller) = serve(MECHANISM_PATH, Mechanism { authority }).await;
    let mechanism = MechanismProxy::new(&caller).await.unwrap();

    assert!(mechanism.may(ACTION_ID).await.unwrap());
    assert!(mechanism.may_fdo(ACTION_ID).await.unwrap());
    for refused in [
        mechanism.may("org.zbus.Unknown").await.unwrap_err(),
        mechanism.may_fdo("org.zbus.Unknown").await.unwrap_err(),
    ] {
        let zbus::Error::MethodError(name, description, _) = &refused else {
            panic!("expected a method error, got {refused:?}");
        };
        assert_eq!(name.as_str(), "org.freedesktop.PolicyKit1.Error.Failed");
        assert_eq!(description.as_deref(), Some("no action org.zbus.Unknown"));
        assert_eq!(
            Error::from(refused),
            Error::Failed("no action org.zbus.Unknown".into())
        );
    }
}

#[tokio::test]
async fn agents_register_for_their_session() {
    let harness = Harness::new().await;
    let proxy = harness.proxy().await;
    let session = Subject::new_for_unix_session("c2");

    proxy
        .register_authentication_agent(&session, "en_US.UTF-8", AGENT_PATH)
        .await
        .unwrap();
    proxy
        .register_authentication_agent_with_options(
            &session,
            "en_US.UTF-8",
            AGENT_PATH,
            &HashMap::from([("fallback", Variant::from(true))]),
        )
        .await
        .unwrap();
    proxy
        .unregister_authentication_agent(&session, AGENT_PATH)
        .await
        .unwrap();

    let authority = harness.authority().await;
    let authority = authority.get().await;
    assert_eq!(authority.subjects.len(), 3);
    assert!(authority
        .subjects
        .iter()
        .all(|subject| subject.session_id() == Some("c2")));
    assert_eq!(*authority.options["fallback"], Variant::from(true));
}

#[tokio::test]
async fn helper_responses_arrive_with_their_identity() {
    let harness = Harness::new().await;
    let proxy = harness.proxy().await;

    proxy
        .authentication_agent_response2(1000, "cookie-1", &Identity::new_for_unix_user(1000))
        .await
        .unwrap();
    proxy
        .authentication_agent_response("cookie-2", &Identity::new_for_unix_netgroup("admins"))
        .await
        .unwrap();

    let authority = harness.authority().await;
    let authority = authority.get().await;
    let [(uid, cookie, user), (no_uid, netgroup_cookie, netgroup)] = &authority.responses[..]
    else {
        panic!("expected two responses, got {:?}", authority.responses);
    };
    assert_eq!((*uid, cookie.as_str()), (Some(1000), "cookie-1"));
    assert_eq!(user.uid(), Some(1000));
    assert_eq!((*no_uid, netgroup_cookie.as_str()), (None, "cookie-2"));
    assert_eq!(netgroup.netgroup(), Some("admins"));
}

#[tokio::test]
async fn a_socket_activated_helper_responds_with_its_agents_process() {
    let harness = Harness::new().await;
    let proxy = harness.proxy().await;
    let pid = rustix::process::getpid();
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();

    proxy
        .authentication_agent_response3(
            "cookie-3",
            &Identity::new_for_unix_user(1001),
            &Subject::new_for_owner(&pidfd, 1000),
        )
        .await
        .unwrap();

    let authority = harness.authority().await;
    let authority = authority.get().await;
    let [(cookie, identity)] = &authority.agent_responses[..] else {
        panic!("expected one response, got {:?}", authority.agent_responses);
    };
    let [agent] = &authority.subjects[..] else {
        panic!("expected one subject, got {:?}", authority.subjects);
    };
    assert_eq!(agent.kind(), "unix-process");
    assert!(agent.pidfd().is_some());
    assert_eq!(agent.uid(), Some(1000));
    assert_eq!(cookie, "cookie-3");
    assert_eq!(identity.uid(), Some(1001));
}

#[tokio::test]
async fn replies_come_back_as_they_were_sent() {
    let harness = Harness::new().await;
    let proxy = harness.proxy().await;

    assert_eq!(
        proxy.enumerate_actions("").await.unwrap(),
        [ActionDescription {
            action_id: ACTION_ID.into(),
            description: DESCRIPTION.into(),
            message: MESSAGE.into(),
            vendor_name: "".into(),
            vendor_url: "".into(),
            icon_name: "".into(),
            implicit_any: ImplicitAuthorization::NotAuthorized,
            implicit_inactive: ImplicitAuthorization::AuthenticationRequired,
            implicit_active: ImplicitAuthorization::Authorized,
            annotations: HashMap::new(),
        }]
    );

    let auths = proxy
        .enumerate_temporary_authorizations(&Subject::new_for_unix_session("c2"))
        .await
        .unwrap();
    let [auth] = &auths[..] else {
        panic!("expected one temporary authorization, got {auths:?}");
    };
    assert_eq!(auth.id, TEMPORARY_AUTHORIZATION_ID);
    assert_eq!(auth.action_id, ACTION_ID);
    assert_eq!(auth.subject.session_id(), Some("c2"));
    assert_eq!((auth.time_obtained, auth.time_expires), (1, 2));

    assert_eq!(
        proxy.backend_features().await.unwrap(),
        AuthorityFeatures::TEMPORARY_AUTHORIZATION
    );
}

/// A mechanism, as far as these tests need one: it asks the authority before it acts, and passes
/// the authority's errors on to its own caller.
struct Mechanism {
    authority: AuthorityProxy<'static>,
}

#[zbus::interface(name = "org.zbus.Mechanism")]
impl Mechanism {
    /// Whether the caller may do `action_id`, as the authority has it.
    async fn may(&self, action_id: &str) -> Result<bool, Error> {
        Ok(self.check(action_id).await?.is_authorized)
    }

    /// The same as `may`, from a method that returns a `zbus::fdo::Result`.
    async fn may_fdo(&self, action_id: &str) -> fdo::Result<bool> {
        Ok(self.check(action_id).await?.is_authorized)
    }
}

impl Mechanism {
    async fn check(&self, action_id: &str) -> zbus::Result<AuthorizationResult<'static>> {
        self.authority
            .check_authorization(
                &Subject::new_for_unix_session("c2"),
                action_id,
                &HashMap::new(),
                CheckAuthorizationFlags::empty(),
                "",
            )
            .await
    }
}

#[zbus::proxy(
    interface = "org.zbus.Mechanism",
    default_service = "org.zbus.Mechanism",
    default_path = "/org/zbus/Mechanism"
)]
trait Mechanism {
    fn may(&self, action_id: &str) -> zbus::Result<bool>;

    fn may_fdo(&self, action_id: &str) -> zbus::Result<bool>;
}

/// A polkit implementation, as far as these tests need one: it keeps what the calls brought, and
/// answers from the one action and the one temporary authorization it knows.
struct Authority {
    /// The one action, as its policy describes it.
    action: Action,
    /// The temporary authorizations it has granted.
    temporary_authorizations: Vec<TemporaryAuthorization<'static>>,
    /// The subject of each call that took one, made owned.
    subjects: Vec<Subject<'static>>,
    /// The details and flags of each `CheckAuthorization`.
    checks: Vec<(HashMap<String, String>, CheckAuthorizationFlags)>,
    /// The options of the last `RegisterAuthenticationAgentWithOptions`.
    options: HashMap<String, OwnedVariant>,
    /// The uid, where one came, the cookie and the identity of each helper's response.
    responses: Vec<(Option<u32>, String, Identity<'static>)>,
    /// The cookie and the identity of each `AuthenticationAgentResponse3`.
    agent_responses: Vec<(String, Identity<'static>)>,
}

impl Authority {
    fn new() -> Self {
        Self {
            action: Action {
                id: ACTION_ID.into(),
                description: DESCRIPTION.into(),
                message: MESSAGE.into(),
                implicit_any: ImplicitAuthorization::NotAuthorized,
                implicit_inactive: ImplicitAuthorization::AuthenticationRequired,
                implicit_active: ImplicitAuthorization::Authorized,
            },
            temporary_authorizations: vec![TemporaryAuthorization {
                id: TEMPORARY_AUTHORIZATION_ID.into(),
                action_id: ACTION_ID.into(),
                subject: Subject::new_for_unix_session("c2"),
                time_obtained: 1,
                time_expires: 2,
            }],
            subjects: Vec::new(),
            checks: Vec::new(),
            options: HashMap::new(),
            responses: Vec::new(),
            agent_responses: Vec::new(),
        }
    }

    fn keep(&mut self, subject: Subject<'_>) -> Result<(), Error> {
        let subject = subject
            .try_into_owned()
            .map_err(|e| Error::Failed(e.to_string().into()))?;
        self.subjects.push(subject);

        Ok(())
    }
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl Authority {
    async fn check_authorization(
        &mut self,
        subject: Subject<'_>,
        action_id: &str,
        details: HashMap<&str, &str>,
        flags: CheckAuthorizationFlags,
        _cancellation_id: &str,
    ) -> Result<AuthorizationResult<'_>, Error> {
        self.keep(subject)?;
        let details = details
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        self.checks.push((details, flags));
        if action_id != self.action.id {
            return Err(Error::Failed(format!("no action {action_id}").into()));
        }

        let granted = &self.temporary_authorizations[0];
        Ok(AuthorizationResult {
            is_authorized: true,
            is_challenge: false,
            details: HashMap::from([(
                "polkit.temporary_authorization_id".into(),
                granted.id.as_ref(),
            )]),
        })
    }

    async fn enumerate_actions(&self, _locale: &str) -> Vec<ActionDescription<'_>> {
        let action = &self.action;

        vec![ActionDescription {
            action_id: action.id.as_str().into(),
            description: action.description.as_str().into(),
            message: action.message.as_str().into(),
            vendor_name: "".into(),
            vendor_url: "".into(),
            icon_name: "".into(),
            implicit_any: action.implicit_any,
            implicit_inactive: action.implicit_inactive,
            implicit_active: action.implicit_active,
            annotations: HashMap::new(),
        }]
    }

    async fn enumerate_temporary_authorizations(
        &self,
        subject: Subject<'_>,
    ) -> Result<Vec<TemporaryAuthorization<'_>>, Error> {
        let Some(session_id) = subject.session_id() else {
            return Err(Error::Failed("not a session".into()));
        };

        self.temporary_authorizations
            .iter()
            .filter(|granted| granted.subject.session_id() == Some(session_id))
            .map(|granted| {
                Ok(TemporaryAuthorization {
                    id: granted.id.as_ref(),
                    action_id: granted.action_id.as_ref(),
                    subject: granted
                        .subject
                        .try_clone()
                        .map_err(|e| Error::Failed(e.to_string().into()))?,
                    time_obtained: granted.time_obtained,
                    time_expires: granted.time_expires,
                })
            })
            .collect()
    }

    async fn register_authentication_agent(
        &mut self,
        subject: Subject<'_>,
        _locale: &str,
        _object_path: &str,
    ) -> Result<(), Error> {
        self.keep(subject)
    }

    async fn register_authentication_agent_with_options(
        &mut self,
        subject: Subject<'_>,
        _locale: &str,
        _object_path: &str,
        options: HashMap<&str, Variant<'_>>,
    ) -> Result<(), Error> {
        self.keep(subject)?;
        self.options = options
            .into_iter()
            .map(|(key, value)| Ok((key.into(), value.try_into_owned()?)))
            .collect::<zbus::Result<_>>()?;

        Ok(())
    }

    async fn unregister_authentication_agent(
        &mut self,
        subject: Subject<'_>,
        _object_path: &str,
    ) -> Result<(), Error> {
        self.keep(subject)
    }

    async fn authentication_agent_response(&mut self, cookie: &str, identity: Identity<'_>) {
        self.responses
            .push((None, cookie.into(), identity.into_owned()));
    }

    async fn authentication_agent_response2(
        &mut self,
        uid: u32,
        cookie: &str,
        identity: Identity<'_>,
    ) {
        self.responses
            .push((Some(uid), cookie.into(), identity.into_owned()));
    }

    async fn authentication_agent_response3(
        &mut self,
        cookie: &str,
        identity: Identity<'_>,
        subject: Subject<'_>,
    ) -> Result<(), Error> {
        self.keep(subject)?;
        self.agent_responses
            .push((cookie.into(), identity.into_owned()));

        Ok(())
    }

    #[zbus(property)]
    fn backend_features(&self) -> AuthorityFeatures {
        AuthorityFeatures::TEMPORARY_AUTHORIZATION
    }
}

/// An action, as the policy of a service describes it.
struct Action {
    id: String,
    description: String,
    message: String,
    implicit_any: ImplicitAuthorization,
    implicit_inactive: ImplicitAuthorization,
    implicit_active: ImplicitAuthorization,
}

fn authorized() -> AuthorizationResult<'static> {
    AuthorizationResult {
        is_authorized: true,
        is_challenge: false,
        details: HashMap::from([(
            "polkit.temporary_authorization_id".into(),
            TEMPORARY_AUTHORIZATION_ID.into(),
        )]),
    }
}

/// An [`Authority`] served on one end of a socket pair, and a connection to it on the other.
struct Harness {
    server: Connection,
    client: Connection,
}

impl Harness {
    async fn new() -> Self {
        let (server, client) = serve(AUTHORITY_PATH, Authority::new()).await;

        Self { server, client }
    }

    async fn proxy(&self) -> AuthorityProxy<'_> {
        // There is no bus to route by name on a peer-to-peer connection, so the default
        // destination reaches the service as any other would.
        AuthorityProxy::new(&self.client).await.unwrap()
    }

    async fn authority(&self) -> InterfaceRef<Authority> {
        self.server
            .object_server()
            .interface(AUTHORITY_PATH)
            .await
            .expect("the authority is served")
    }
}

/// `interface`, served at `path` on one end of a socket pair, and a connection to it on the other,
/// in that order.
async fn serve<I>(path: &str, interface: I) -> (Connection, Connection)
where
    I: Interface,
{
    let (server_stream, client_stream) = std::os::unix::net::UnixStream::pair().unwrap();
    let server = connection::Builder::unix_stream(server_stream)
        .server(Guid::generate())
        .p2p()
        .serve_at(path, interface)
        .build();
    let client = connection::Builder::unix_stream(client_stream)
        .p2p()
        .build();
    // Both ends have to make progress for the peer-to-peer handshake to finish.
    future::try_join(server, client)
        .await
        .expect("p2p handshake")
}

const ACTION_ID: &str = "org.zbus.BeAwesome";
const DESCRIPTION: &str = "Be awesome";
const MESSAGE: &str = "Authentication is required to be awesome";
const TEMPORARY_AUTHORIZATION_ID: &str = "tmp-1";
const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const AGENT_PATH: &str = "/org/freedesktop/PolicyKit1/AuthenticationAgent";
const MECHANISM_PATH: &str = "/org/zbus/Mechanism";
