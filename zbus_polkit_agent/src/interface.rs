use crate::Identity;
use crate::server::Error;
use std::collections::HashMap;

pub trait PolkitCore: Sync + Send {
    type State;
    fn boot(&self) -> Self::State;
    #[allow(clippy::too_many_arguments)]
    fn authenticate<'a>(
        &'a mut self,
        state: &'a mut Self::State,
        action_id: &'a str,
        message: &'a str,
        icon_name: &'a str,
        details: HashMap<&'a str, &'a str>,
        cookie: &'a str,
        identifies: Vec<Identity<'a>>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    fn cancel_authentication<'a>(
        &'a mut self,
        state: &'a mut Self::State,
        cookie: &'a str,
    ) -> impl Future<Output = Result<(), Error>> + Send;
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
    async fn begin_authentication(
        &mut self,
        action_id: &str,
        msg: &str,
        icon_name: &str,
        details: HashMap<&str, &str>,
        cookie: &str,
        identifies: Vec<Identity<'_>>,
    ) -> Result<(), Error> {
        self.agent
            .authenticate(
                &mut self.state,
                action_id,
                msg,
                icon_name,
                details,
                cookie,
                identifies,
            )
            .await
    }
    async fn cancel_authentication(&mut self, cookie: &str) -> Result<(), Error> {
        self.agent
            .cancel_authentication(&mut self.state, cookie)
            .await
    }
}

pub trait Authenticate<'a, State>
where
    State: 'a,
{
    type Future: Future<Output = Result<(), Error>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn authenticate(
        &'a mut self,
        state: &'a mut State,
        action_id: &'a str,
        message: &'a str,
        icon_name: &'a str,
        details: HashMap<&'a str, &'a str>,
        cookie: &'a str,
        identifies: Vec<Identity<'a>>,
    ) -> Self::Future;
}
impl<'a, F, State, Fut> Authenticate<'a, State> for F
where
    F: Fn(
        &'a mut State,
        &'a str,
        &'a str,
        &'a str,
        HashMap<&'a str, &'a str>,
        &'a str,
        Vec<Identity<'a>>,
    ) -> Fut,
    Fut: Future<Output = Result<(), Error>> + Send,
    State: 'a,
{
    type Future = Fut;
    fn authenticate(
        &'a mut self,
        state: &'a mut State,
        action_id: &'a str,
        message: &'a str,
        icon_name: &'a str,
        details: HashMap<&'a str, &'a str>,
        cookie: &'a str,
        identifies: Vec<Identity<'a>>,
    ) -> Self::Future {
        self(
            state, action_id, message, icon_name, details, cookie, identifies,
        )
    }
}
pub trait CancelAuthentication<'a, State>
where
    State: 'a,
{
    type Future: Future<Output = Result<(), Error>> + Send;
    fn cancel_authentication(&'a self, state: &'a mut State, cookie: &'a str) -> Self::Future;
}

impl<'a, F, State, Fut> CancelAuthentication<'a, State> for F
where
    Fut: Future<Output = Result<(), Error>> + Send,
    F: Fn(&'a mut State, &'a str) -> Fut,
    State: 'a,
{
    type Future = Fut;
    fn cancel_authentication(&'a self, state: &'a mut State, cookie: &'a str) -> Self::Future {
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
