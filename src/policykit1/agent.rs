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
//!         Err(Error::Cancelled(format!(
//!             "not authenticating for {}",
//!             request.action_id
//!         )))
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
    borrow::Cow,
    collections::{HashMap, VecDeque},
    fmt,
    future::{poll_fn, Future},
    pin::pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Poll, Waker},
};

use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer,
};
use static_assertions::assert_impl_all;
use zbus::{Signature, Type};

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
        details: Details<'_>,
        cookie: &str,
        identities: Vec<Identity<'_>>,
    ) -> Result<(), Error> {
        let tracked = self.cancellations.begin(cookie)?;
        let request = Request {
            action_id: action_id.into(),
            message: message.into(),
            icon_name: icon_name.into(),
            details: details.0,
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
#[derive(Debug, Clone, PartialEq)]
pub struct Request<'a> {
    /// The action the user is authenticating for.
    pub action_id: Cow<'a, str>,

    /// The message to show the user, in the locale the agent registered with.
    pub message: Cow<'a, str>,

    /// The name of an icon to show with the message, or empty for none.
    pub icon_name: Cow<'a, str>,

    /// The details the mechanism gave `CheckAuthorization()`, plus what the daemon adds.
    pub details: HashMap<Cow<'a, str>, Cow<'a, str>>,

    /// What names this authentication to the daemon; the helper reports with it.
    pub cookie: Cow<'a, str>,

    /// Who may authenticate for the action. The user picks one of these, or the agent picks for
    /// them.
    pub identities: Vec<Identity<'a>>,
}

impl Request<'_> {
    /// This request with all of its text owned, so that it borrows from nothing.
    pub fn into_owned(self) -> Request<'static> {
        fn owned(text: Cow<'_, str>) -> Cow<'static, str> {
            text.into_owned().into()
        }

        Request {
            action_id: owned(self.action_id),
            message: owned(self.message),
            icon_name: owned(self.icon_name),
            details: self
                .details
                .into_iter()
                .map(|(key, value)| (owned(key), owned(value)))
                .collect(),
            cookie: owned(self.cookie),
            identities: self
                .identities
                .into_iter()
                .map(Identity::into_owned)
                .collect(),
        }
    }
}

assert_impl_all!(Request<'_>: Send, Sync, Unpin);

/// The details of a `BeginAuthentication` call, decoded straight into the map a [`Request`] holds
/// them in, borrowing every key and value from the call.
struct Details<'a>(HashMap<Cow<'a, str>, Cow<'a, str>>);

impl Type for Details<'_> {
    const SIGNATURE: &'static Signature = <HashMap<&str, &str>>::SIGNATURE;
}

impl<'de> Deserialize<'de> for Details<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Entries;

        impl<'de> Visitor<'de> for Entries {
            type Value = Details<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a dictionary of strings")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut details = HashMap::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((key, value)) = map.next_entry::<&str, &str>()? {
                    details.insert(Cow::Borrowed(key), Cow::Borrowed(value));
                }

                Ok(Details(details))
            }
        }

        deserializer.deserialize_map(Entries)
    }
}

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
            return Err(Error::Failed(format!(
                "an authentication for cookie {cookie} is already running"
            )));
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
    use zbus::object_server::Interface;

    use super::*;

    #[test]
    fn interface_is_the_one_the_daemon_calls() {
        assert_eq!(
            Agent::<Declining>::name().as_str(),
            "org.freedesktop.PolicyKit1.AuthenticationAgent"
        );
    }

    struct Declining;

    impl Handler for Declining {
        async fn begin_authentication(&self, _request: Request<'_>) -> Result<(), Error> {
            Err(Error::Cancelled("declined".into()))
        }
    }
}
