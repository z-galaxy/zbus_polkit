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
//!     async fn begin_authentication(&self, request: Request) -> Result<(), Error> {
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
    collections::{HashMap, VecDeque},
    future::{poll_fn, Future},
    pin::pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Poll, Waker},
};

use static_assertions::assert_impl_all;

use super::{Error, OwnedIdentity};

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
        action_id: String,
        message: String,
        icon_name: String,
        details: HashMap<String, String>,
        cookie: String,
        identities: Vec<OwnedIdentity>,
    ) -> Result<(), Error> {
        let tracked = self.cancellations.begin(&cookie)?;
        let request = Request {
            action_id,
            message,
            icon_name,
            details,
            cookie: cookie.clone(),
            identities,
        };
        let cancellation = async {
            tracked.cancelled().await;

            Err(cancelled())
        };

        race(cancellation, self.handler.begin_authentication(request)).await
    }

    fn cancel_authentication(&self, cookie: String) {
        self.cancellations.cancel(cookie);
    }
}

/// What an agent does when the user has to authenticate.
///
/// An [`Agent`] hands each request over as the daemon makes it, so several may be running at once.
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
        request: Request,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

impl<H: Handler> Handler for Arc<H> {
    fn begin_authentication(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        (**self).begin_authentication(request)
    }
}

/// What the daemon sends an agent when the user has to authenticate: the arguments of
/// `BeginAuthentication`, as the types polkit documents.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// The action the user is authenticating for.
    pub action_id: String,

    /// The message to show the user, in the locale the agent registered with.
    pub message: String,

    /// The name of an icon to show with the message, or empty for none.
    pub icon_name: String,

    /// The details the mechanism gave `CheckAuthorization()`, plus what the daemon adds.
    pub details: HashMap<String, String>,

    /// What names this authentication to the daemon; the helper reports with it.
    pub cookie: String,

    /// Who may authenticate for the action. The user picks one of these, or the agent picks for
    /// them.
    pub identities: Vec<OwnedIdentity>,
}

assert_impl_all!(Request: Send, Sync, Unpin);

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
    running: HashMap<String, Running>,
    early: VecDeque<String>,
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
        if let Some(i) = state.early.iter().position(|early| early == cookie) {
            state.early.remove(i);

            return Err(cancelled());
        }
        if state.running.contains_key(cookie) {
            return Err(Error::Failed(format!(
                "an authentication for cookie {cookie} is already running"
            )));
        }
        state.running.insert(cookie.to_owned(), Running::default());

        Ok(Tracked {
            cancellations: self,
            cookie,
        })
    }

    fn cancel(&self, cookie: String) {
        let mut guard = self.lock();
        let state = &mut *guard;
        let waker = match state.running.get_mut(&cookie) {
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
                state.early.push_back(cookie);
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

    struct Declining;

    impl Handler for Declining {
        async fn begin_authentication(&self, _request: Request) -> Result<(), Error> {
            Err(Error::Cancelled("declined".into()))
        }
    }

    #[test]
    fn interface_is_the_one_the_daemon_calls() {
        assert_eq!(
            Agent::<Declining>::name().as_str(),
            "org.freedesktop.PolicyKit1.AuthenticationAgent"
        );
    }
}
