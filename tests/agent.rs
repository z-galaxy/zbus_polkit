//! Drive `agent::Agent` from the other end of a peer-to-peer connection, standing in for the
//! daemon, and check what reaches the handler and what comes back.

#![cfg(all(unix, feature = "agent"))]

use std::{collections::HashMap, time::Duration};

use futures_util::future;
use tokio::sync::{mpsc, oneshot};
use zbus::{connection, fdo::IntrospectableProxy, Connection, Guid};
use zbus_polkit::policykit1::{
    agent::{self, Agent, Handler, Request},
    AuthenticationAgentProxy, Error, OwnedIdentity,
};

#[tokio::test]
async fn begin_authentication_arrives_typed_and_waits_for_the_handler() {
    let mut harness = Harness::new().await;

    let call = tokio::spawn({
        let proxy = harness.proxy.clone();
        async move {
            proxy
                .begin_authentication(
                    "org.zbus.BeAwesome",
                    "Authentication is required to be awesome",
                    "security-high",
                    &HashMap::from([("polkit.caller-pid", "4242")]),
                    "cookie-1",
                    &[
                        OwnedIdentity::new_for_unix_user(1000),
                        OwnedIdentity::new_for_unix_group(27),
                    ],
                )
                .await
        }
    });

    let Begun { request, outcome } = harness.begun.recv().await.expect("the handler is told");
    assert_eq!(request.action_id, "org.zbus.BeAwesome");
    assert_eq!(request.message, "Authentication is required to be awesome");
    assert_eq!(request.icon_name, "security-high");
    assert_eq!(
        request.details,
        HashMap::from([("polkit.caller-pid".to_string(), "4242".to_string())])
    );
    assert_eq!(request.cookie, "cookie-1");
    // The identities arrive as the types polkit documents, not as a kind string and a map.
    assert_eq!(request.identities.len(), 2);
    assert_eq!(request.identities[0].kind(), "unix-user");
    assert_eq!(request.identities[0].uid(), Some(1000));
    assert_eq!(request.identities[1].kind(), "unix-group");
    assert_eq!(request.identities[1].gid(), Some(27));

    // The daemon's call is answered by the handler, and not before.
    assert!(!call.is_finished());
    outcome.send(Ok(())).unwrap();
    call.await
        .unwrap()
        .expect("a successful authentication is an empty reply");
}

#[tokio::test]
async fn how_the_authentication_ended_is_the_reply() {
    let mut harness = Harness::new().await;

    let call = tokio::spawn({
        let proxy = harness.proxy.clone();
        async move {
            proxy
                .begin_authentication(
                    "org.zbus.BeAwesome",
                    "",
                    "",
                    &HashMap::new(),
                    "cookie-2",
                    &[],
                )
                .await
        }
    });

    let Begun { outcome, .. } = harness.begun.recv().await.unwrap();
    outcome
        .send(Err(Error::Cancelled("dismissed".into())))
        .unwrap();

    // What the daemon sees is a method error in the polkit domain.
    assert_eq!(
        call.await.unwrap(),
        Err(Error::Cancelled("dismissed".into()))
    );
}

#[tokio::test]
async fn cancelling_drops_the_running_authentication() {
    let mut harness = Harness::new().await;

    let call = tokio::spawn({
        let proxy = harness.proxy.clone();
        async move {
            proxy
                .begin_authentication(
                    "org.zbus.BeAwesome",
                    "",
                    "",
                    &HashMap::new(),
                    "cookie-3",
                    &[],
                )
                .await
        }
    });
    let Begun { mut outcome, .. } = harness.begun.recv().await.unwrap();

    harness
        .proxy
        .cancel_authentication("cookie-3")
        .await
        .expect("CancelAuthentication has no error reply");

    outcome.closed().await;
    assert!(matches!(call.await.unwrap(), Err(Error::Cancelled(_))));
}

// zbus handles each call in a task of its own, so a cancellation sent right behind its begin can
// be handled first. It still has to cancel it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancellation_overtaking_its_begin_still_cancels_it() {
    let harness = Harness::new().await;

    let pairs = async {
        for i in 0..1000 {
            let cookie = format!("cookie-{i}");
            let (begun, cancelled) = future::join(
                harness.proxy.begin_authentication(
                    "org.zbus.BeAwesome",
                    "",
                    "",
                    &HashMap::new(),
                    &cookie,
                    &[],
                ),
                harness.proxy.cancel_authentication(&cookie),
            )
            .await;

            cancelled.unwrap();
            assert!(matches!(begun, Err(Error::Cancelled(_))), "{cookie}");
        }
    };

    tokio::time::timeout(Duration::from_secs(60), pairs)
        .await
        .expect("every authentication is cancelled");
}

#[tokio::test]
async fn authentications_run_concurrently() {
    let mut harness = Harness::new().await;

    let begin = |cookie: &'static str| {
        let proxy = harness.proxy.clone();
        tokio::spawn(async move {
            proxy
                .begin_authentication("org.zbus.BeAwesome", "", "", &HashMap::new(), cookie, &[])
                .await
        })
    };
    let first = begin("cookie-a");
    let second = begin("cookie-b");

    let mut pending: HashMap<String, oneshot::Sender<Result<(), Error>>> = HashMap::new();
    for _ in 0..2 {
        let Begun { request, outcome } = harness.begun.recv().await.unwrap();
        pending.insert(request.cookie, outcome);
    }
    assert!(!first.is_finished() && !second.is_finished());

    pending.remove("cookie-b").unwrap().send(Ok(())).unwrap();
    second.await.unwrap().unwrap();
    assert!(!first.is_finished());
    pending.remove("cookie-a").unwrap().send(Ok(())).unwrap();
    first.await.unwrap().unwrap();
}

// The served interface has to be the one polkit's own XML describes, argument types included, or
// the daemon's calls would not decode.
#[tokio::test]
async fn introspection_matches_polkit() {
    let harness = Harness::new().await;

    let xml = IntrospectableProxy::builder(&harness.client)
        .destination(DESTINATION)
        .path(agent::OBJECT_PATH)
        .build()
        .await
        .unwrap()
        .introspect()
        .await
        .unwrap();

    assert!(xml.contains(r#"<interface name="org.freedesktop.PolicyKit1.AuthenticationAgent">"#));
    assert!(xml.contains(r#"<method name="BeginAuthentication">"#));
    assert!(xml.contains(r#"<method name="CancelAuthentication">"#));
    for (name, signature) in [
        ("action_id", "s"),
        ("message", "s"),
        ("icon_name", "s"),
        ("details", "a{ss}"),
        ("cookie", "s"),
        ("identities", "a(sa{sv})"),
    ] {
        let arg = format!(r#"name="{name}" type="{signature}""#);
        assert!(xml.contains(&arg), "{arg} is not in:\n{xml}");
    }
}

/// An [`Agent`] served on one end of a socket pair, a proxy to it on the other, and the handler's
/// view of what arrived.
struct Harness {
    /// The agent's end, kept alive for as long as the harness is.
    _server: Connection,
    client: Connection,
    proxy: AuthenticationAgentProxy<'static>,
    begun: mpsc::UnboundedReceiver<Begun>,
}

impl Harness {
    async fn new() -> Self {
        let (begun_tx, begun) = mpsc::unbounded_channel();
        let agent = Agent::new(Relay { begun: begun_tx });

        let (server_stream, client_stream) = std::os::unix::net::UnixStream::pair().unwrap();
        let server = connection::Builder::unix_stream(server_stream)
            .server(Guid::generate())
            .p2p()
            .serve_at(agent::OBJECT_PATH, agent)
            .build();
        let client = connection::Builder::unix_stream(client_stream)
            .p2p()
            .build();
        // Both ends have to make progress for the peer-to-peer handshake to finish.
        let (server, client) = future::try_join(server, client)
            .await
            .expect("p2p handshake");

        let proxy = AuthenticationAgentProxy::builder(&client)
            .destination(DESTINATION)
            .path(agent::OBJECT_PATH)
            .build()
            .await
            .expect("build the proxy");

        Self {
            _server: server,
            client,
            proxy,
            begun,
        }
    }
}

/// A handler that relays what the daemon sends to the test, and lets it decide how each
/// authentication ends.
struct Relay {
    begun: mpsc::UnboundedSender<Begun>,
}

/// A `BeginAuthentication` the handler received, and the way to answer it.
struct Begun {
    request: Request,
    outcome: oneshot::Sender<Result<(), Error>>,
}

impl Handler for Relay {
    async fn begin_authentication(&self, request: Request) -> Result<(), Error> {
        let (outcome, decided) = oneshot::channel();
        self.begun
            .send(Begun { request, outcome })
            .expect("the test is listening");

        decided
            .await
            .expect("the test decides how the authentication ends")
    }
}

/// There is no bus to route by name on a peer-to-peer connection, so any destination reaches the
/// agent; the daemon would use the agent's unique name.
const DESTINATION: &str = ":1.0";
