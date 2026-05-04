use crate::{Error, Identity};
use std::collections::HashMap;

pub trait PolkitCore: Sync + Send {
    type State;
    fn boot(&self) -> Self::State;
    #[allow(clippy::too_many_arguments)]
    fn authenticate(
        &mut self,
        state: &mut Self::State,
        action_id: &str,
        message: &str,
        icon_name: &str,
        details: HashMap<&str, &str>,
        identifies: Vec<Identity<'_>>,
        cookie: &str,
    ) -> Result<(), Error>;

    fn cancel_authentication(&mut self, state: &mut Self::State, cookie: &str)
    -> Result<(), Error>;
}

pub struct PolkitAgentBuilder<C: PolkitCore> {
    pub(crate) agent: C,
}

pub struct PolkitAgent<C: PolkitCore<State = State>, State> {
    pub(crate) agent: C,
    pub(crate) state: State,
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl<C: PolkitCore<State = State> + 'static, State> PolkitAgent<C, State>
where
    State: 'static + Sync + Send,
{
    fn begin_authentication(
        &mut self,
        action_id: &str,
        msg: &str,
        icon_name: &str,
        details: HashMap<&str, &str>,
        cookie: &str,
        identifies: Vec<Identity<'_>>,
    ) -> Result<(), Error> {
        self.agent.authenticate(
            &mut self.state,
            action_id,
            msg,
            icon_name,
            details,
            identifies,
            cookie,
        )
    }
    fn cancel_authentication(&mut self, cookie: &str) -> Result<(), Error> {
        self.agent.cancel_authentication(&mut self.state, cookie)
    }
}

pub trait Authenticate<State> {
    #[allow(clippy::too_many_arguments)]
    fn authenticate(
        &self,
        state: &mut State,
        action_id: &str,
        message: &str,
        icon_name: &str,
        details: HashMap<&str, &str>,
        cookie: &str,
        identifies: Vec<Identity<'_>>,
    ) -> Result<(), Error>;
}
impl<F, State> Authenticate<State> for F
where
    F: Fn(
        &mut State,
        &str,
        &str,
        &str,
        HashMap<&str, &str>,
        &str,
        Vec<Identity<'_>>,
    ) -> Result<(), Error>,
{
    fn authenticate(
        &self,
        state: &mut State,
        action_id: &str,
        message: &str,
        icon_name: &str,
        details: HashMap<&str, &str>,
        cookie: &str,
        identifies: Vec<Identity<'_>>,
    ) -> Result<(), Error> {
        self(
            state, action_id, message, icon_name, details, cookie, identifies,
        )
    }
}
pub trait CancelAuthentication<State> {
    fn cancel_authentication(&self, state: &mut State, cookie: &str) -> Result<(), Error>;
}

impl<F, State> CancelAuthentication<State> for F
where
    F: Fn(&mut State, &str) -> Result<(), Error>,
{
    fn cancel_authentication(&self, state: &mut State, cookie: &str) -> Result<(), Error> {
        self(state, cookie)
    }
}

pub trait Boot<State> {
    fn boot(&self) -> State;
}
impl<F, State> Boot<State> for F
where
    F: Fn() -> State,
{
    fn boot(&self) -> State {
        self()
    }
}
