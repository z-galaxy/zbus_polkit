//! Being an authentication agent: the side of polkit that asks the user to authenticate.
//!
//! The daemon calls `BeginAuthentication` on an agent whenever an authorization check it is
//! handling needs the user to authenticate, and `CancelAuthentication` when that check goes away
//! first. An agent is an object implementing that interface, served on the system bus and
//! registered with the daemon, through
//! [`AuthorityProxy::register_authentication_agent`](super::AuthorityProxy::register_authentication_agent),
//! for the session it serves.
//!
//! [`Agent`] is that object. It decodes what the daemon sends into a [`Request`] and hands it to
//! the [`Handler`] it was built with, which is where an agent's own behaviour lives: showing the
//! request, collecting the user's credentials and having them checked. A cancellation drops the
//! handler's future for that request. The check itself is done by polkit's setuid helper,
//! `polkit-agent-helper-1`, which reports the outcome to the daemon on its own; the agent only
//! reports how the attempt ended. Running the helper is left to the handler.
//!
//! ```
//! use zbus::connection;
//! use zbus_polkit::policykit1::{
//!     agent::{self, Agent, Handler, Request},
//!     AuthorityProxy, Error, Subject,
//! };
//!
//! struct Prompt;
//!
//! impl Handler for Prompt {
//!     async fn begin_authentication(&self, request: Request<'_>) -> Result<(), Error> {
//!         // Show `request` to the user and run the helper. This agent only ever declines.
//!         Err(Error::Cancelled(
//!             format!("not authenticating for {}", request.action_id).into(),
//!         ))
//!     }
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let connection = connection::Builder::system()
//!     .serve_at(agent::OBJECT_PATH, Agent::new(Prompt))
//!     .build()
//!     .await?;
//!
//! let session = Subject::new_for_unix_session(std::env::var("XDG_SESSION_ID")?);
//! AuthorityProxy::new(&connection)
//!     .await?
//!     .register_authentication_agent(&session, "en_US.UTF-8", agent::OBJECT_PATH)
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::{
    collections::{HashMap, VecDeque},
    future::{poll_fn, Future},
    pin::pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Poll, Waker},
};

use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;
use zbus::{Str, Type};

use super::{Error, Identity};

/// The object the daemon calls, decoding what it sends into a [`Request`] for a [`Handler`].
///
/// Serve it on the system bus, at [`OBJECT_PATH`] by convention, and register that path with the
/// daemon for the session the agent is for.
pub struct Agent<H> {
    handler: H,
    cancellations: Cancellations,
}

impl<H: Handler> Agent<H> {
    /// An agent that hands everything the daemon sends to `handler`.
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            cancellations: Cancellations::default(),
        }
    }

    /// The handler this agent was built with.
    pub fn handler(&self) -> &H {
        &self.handler
    }
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl<H: Handler> Agent<H> {
    async fn begin_authentication(
        &self,
        action_id: &str,
        message: &str,
        icon_name: &str,
        details: HashMap<Str<'_>, Str<'_>>,
        cookie: &str,
        identities: Vec<Identity<'_>>,
    ) -> Result<(), Error> {
        let tracked = self.cancellations.begin(cookie)?;
        let request = Request {
            action_id: action_id.into(),
            message: message.into(),
            icon_name: icon_name.into(),
            details,
            cookie: cookie.into(),
            identities,
        };
        let cancellation = async {
            tracked.cancelled().await;

            Err(cancelled())
        };

        race(cancellation, self.handler.begin_authentication(request)).await
    }

    fn cancel_authentication(&self, cookie: &str) {
        self.cancellations.cancel(cookie);
    }
}

/// What an agent does when the user has to authenticate.
///
/// An [`Agent`] hands each request over as the daemon makes it, so several may be running at once.
/// A request borrows from the daemon's call, so a handler that passes it on to another task or
/// thread makes it owned first, with [`Request::into_owned`].
/// If the daemon cancels one, the agent drops its future and replies [`Error::Cancelled`] itself,
/// so whatever the handler started for it, a prompt or the helper, has to go with the future, e.g.
/// in a destructor.
///
/// `Arc<H>` is a `Handler` whenever `H` is, so an agent can share its handler with the rest of the
/// program.
pub trait Handler: Send + Sync + 'static {
    /// Authenticate the user for `request`, and report how that went.
    ///
    /// The daemon's call waits for this to return. Return `Ok(())` once the helper has reported a
    /// successful authentication to the daemon, [`Error::Cancelled`] if the user dismissed the
    /// request, which the daemon passes on to the mechanism as `polkit.dismissed`, and
    /// [`Error::Failed`] for anything else.
    fn begin_authentication(
        &self,
        request: Request<'_>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

impl<H: Handler> Handler for Arc<H> {
    fn begin_authentication(
        &self,
        request: Request<'_>,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        (**self).begin_authentication(request)
    }
}

/// What the daemon sends an agent when the user has to authenticate: the arguments of
/// `BeginAuthentication`, as the types polkit documents.
///
/// It borrows its text from the daemon's call, which lasts for as long as
/// [`Handler::begin_authentication`] runs. [`into_owned`](Self::into_owned) is for a request that
/// has to go further than that, to another task or thread.
///
/// It serializes as a struct of those arguments, under the names polkit gives them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Type)]
pub struct Request<'a> {
    /// The action the user is authenticating for.
    #[serde(borrow)]
    pub action_id: Str<'a>,

    /// The message to show the user, in the locale the agent registered with.
    #[serde(borrow)]
    pub message: Str<'a>,

    /// The name of an icon to show with the message, or empty for none.
    #[serde(borrow)]
    pub icon_name: Str<'a>,

    /// The details the mechanism gave `CheckAuthorization()`, plus what the daemon adds.
    #[serde(borrow)]
    pub details: HashMap<Str<'a>, Str<'a>>,

    /// What names this authentication to the daemon; the helper reports with it.
    #[serde(borrow)]
    pub cookie: Str<'a>,

    /// Who may authenticate for the action. The user picks one of these, or the agent picks for
    /// them.
    #[serde(borrow)]
    pub identities: Vec<Identity<'a>>,
}

impl Request<'_> {
    /// This request with all of its text owned, so that it borrows from nothing.
    pub fn into_owned(self) -> Request<'static> {
        Request {
            action_id: self.action_id.into_owned(),
            message: self.message.into_owned(),
            icon_name: self.icon_name.into_owned(),
            details: self
                .details
                .into_iter()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect(),
            cookie: self.cookie.into_owned(),
            identities: self
                .identities
                .into_iter()
                .map(Identity::into_owned)
                .collect(),
        }
    }
}

assert_impl_all!(Request<'_>: Send, Sync, Unpin);

/// The object path agents conventionally serve at; polkit's own agents do.
pub const OBJECT_PATH: &str = "/org/freedesktop/PolicyKit1/AuthenticationAgent";

/// The authentications the daemon has cancelled, by cookie.
///
/// zbus handles each call in a task of its own, so a `CancelAuthentication` sent right behind its
/// `BeginAuthentication` can be handled first. Such a cancellation is kept for the begin that is
/// about to arrive.
#[derive(Default)]
struct Cancellations(Mutex<State>);

#[derive(Default)]
struct State {
    running: HashMap<Box<str>, Running>,
    early: VecDeque<Box<str>>,
}

#[derive(Default)]
struct Running {
    cancelled: bool,
    waker: Option<Waker>,
}

impl Cancellations {
    /// Track the authentication for `cookie` until the returned value is dropped.
    fn begin<'a>(&'a self, cookie: &'a str) -> Result<Tracked<'a>, Error> {
        let mut state = self.lock();
        if let Some(i) = state.early.iter().position(|early| &**early == cookie) {
            state.early.remove(i);

            return Err(cancelled());
        }
        if state.running.contains_key(cookie) {
            return Err(Error::Failed(
                format!("an authentication for cookie {cookie} is already running").into(),
            ));
        }
        state.running.insert(cookie.into(), Running::default());

        Ok(Tracked {
            cancellations: self,
            cookie,
        })
    }

    fn cancel(&self, cookie: &str) {
        let mut guard = self.lock();
        let state = &mut *guard;
        let waker = match state.running.get_mut(cookie) {
            Some(running) => {
                running.cancelled = true;
                running.waker.take()
            }
            None => {
                // A cancellation that crossed the reply to its begin never gets one, so they are
                // not kept without bound.
                if state.early.len() == EARLY_CANCELLATIONS {
                    state.early.pop_front();
                }
                state.early.push_back(cookie.into());
                None
            }
        };
        drop(guard);

        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// An authentication [`Cancellations`] tracks while this is alive.
struct Tracked<'a> {
    cancellations: &'a Cancellations,
    cookie: &'a str,
}

impl Tracked<'_> {
    /// Resolves once the daemon has cancelled the authentication.
    async fn cancelled(&self) {
        poll_fn(|cx| {
            let mut state = self.cancellations.lock();
            let running = state
                .running
                .get_mut(self.cookie)
                .expect("tracked until dropped");
            if running.cancelled {
                return Poll::Ready(());
            }
            running.waker = Some(cx.waker().clone());

            Poll::Pending
        })
        .await
    }
}

impl Drop for Tracked<'_> {
    fn drop(&mut self) {
        self.cancellations.lock().running.remove(self.cookie);
    }
}

/// Whichever of `first` and `second` finishes first, `first` winning a tie.
async fn race<T>(first: impl Future<Output = T>, second: impl Future<Output = T>) -> T {
    let (mut first, mut second) = (pin!(first), pin!(second));

    poll_fn(|cx| match first.as_mut().poll(cx) {
        Poll::Pending => second.as_mut().poll(cx),
        ready => ready,
    })
    .await
}

fn cancelled() -> Error {
    Error::Cancelled("the authority cancelled the authentication".into())
}

/// How many cancellations are kept for authentications that have not begun. One waits only for
/// the moment until its begin is handled.
const EARLY_CANCELLATIONS: usize = 64;

#[cfg(test)]
mod tests {
    use zbus::{
        object_server::Interface,
        wire::{serialized::Context, to_bytes, LE},
    };

    use super::*;

    #[test]
    fn interface_is_the_one_the_daemon_calls() {
        assert_eq!(
            Agent::<Declining>::name().as_str(),
            "org.freedesktop.PolicyKit1.AuthenticationAgent"
        );
    }

    // A service can hand a request over to its next instance in zbus's own format, which carries
    // the descriptors that the rest of what it hands over may hold.
    #[test]
    fn request_round_trips_through_the_wire_format() {
        assert_eq!(Request::SIGNATURE.to_string(), "(sssa{ss}sa(sa{sv}))");

        let request = Request {
            action_id: "org.zbus.BeAwesome".into(),
            message: "Authentication is required to be awesome".into(),
            icon_name: "security-high".into(),
            details: HashMap::from([("polkit.caller-pid".into(), "4242".into())]),
            cookie: "cookie-1".into(),
            identities: vec![Identity::new_for_unix_user(1000)],
        };
        let encoded = to_bytes(Context::new(LE, 0), &request).unwrap();
        let decoded: Request<'_> = encoded.deserialize().unwrap().0;
        assert_eq!(decoded, request);
        // Decoded, the text is the encoding's own, not a copy of it.
        let within = |text: &str| encoded.as_ptr_range().contains(&text.as_ptr());
        assert!(within(&decoded.action_id) && within(&decoded.cookie));
        assert!(decoded
            .details
            .iter()
            .all(|(key, value)| within(key) && within(value)));
    }

    // `from_str` lends the strings it does not have to unescape, and a `Value` lends none, so both
    // are tried.
    #[test]
    fn request_round_trips_through_a_self_describing_format() {
        let request = Request {
            action_id: "org.zbus.BeAwesome".into(),
            message: "Authenticate to be \"awesome\"".into(),
            icon_name: "".into(),
            details: HashMap::from([("polkit.caller-pid".into(), "4242".into())]),
            cookie: "cookie-1".into(),
            identities: vec![
                Identity::new_for_unix_user(1000),
                Identity::new_for_unix_netgroup("admins"),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let back: Request<'_> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, request);
        // The text that needed no unescaping is the input's own, not a copy of it.
        let action_id = back.action_id.as_borrowed().unwrap();
        assert!(json.as_bytes().as_ptr_range().contains(&action_id.as_ptr()));
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(Request::deserialize(value).unwrap(), request);
    }

    struct Declining;

    impl Handler for Declining {
        async fn begin_authentication(&self, _request: Request<'_>) -> Result<(), Error> {
            Err(Error::Cancelled("declined".into()))
        }
    }
}
