pub mod agent_session;
pub mod error;
mod unixsession;
use std::{collections::HashMap, marker::PhantomData};
use zbus::connection;
pub use zbus_polkit::identify::*;
mod interface;
use interface::*;

use zbus_polkit::policykit1::AuthorityProxy;

use crate::unixsession::UnixSession;

pub mod reexport {
    pub use zbus::Connection;
}

pub mod server {
    #[derive(Clone, Debug, zbus::DBusError)]
    #[zbus(prefix = "org.freedesktop.PolicyKit1.Error")]
    pub enum Error {
        Failed,
        FailedWithReason(String),
        Cancelled,
        NotSupported,
        NotAuthorized,
        CancellationIdNotUnique,
    }

    impl From<crate::error::Error> for Error {
        fn from(value: crate::error::Error) -> Self {
            Self::FailedWithReason(value.to_string())
        }
    }
    impl From<zbus_polkit::Error> for Error {
        fn from(value: zbus_polkit::Error) -> Self {
            Self::FailedWithReason(value.to_string())
        }
    }
}

use server::Error;

pub fn polkit_agent_instance<Authenticate, CancelAuthentication, State, Boot>(
    boot: Boot,
    authenticate: Authenticate,
    cancel_authentication: CancelAuthentication,
) -> PolkitAgentBuilder<impl PolkitCore<State = State>>
where
    Boot: self::Boot<State> + Send + Sync,
    Authenticate: for<'a> self::Authenticate<'a, State> + Send + Sync,
    CancelAuthentication: for<'a> self::CancelAuthentication<'a, State> + Send + Sync,
    State: 'static + Send + Sync,
{
    struct Instance<State, Boot, Authenticate, CancelAuthentication> {
        boot: Option<Boot>,
        authenticate: Authenticate,
        cancel_authentication: CancelAuthentication,
        _state: PhantomData<State>,
    }
    impl<State, Boot, Authenticate, CancelAuthentication> PolkitCore
        for Instance<State, Boot, Authenticate, CancelAuthentication>
    where
        Boot: self::Boot<State> + Sync + Send,
        Authenticate: for<'a> self::Authenticate<'a, State> + Sync + Send,
        CancelAuthentication: for<'a> self::CancelAuthentication<'a, State> + Send + Sync,
        State: 'static + Send + Sync,
    {
        type State = State;
        fn boot(&mut self) -> Self::State {
            self.boot.take().expect("Only run once a time").boot()
        }

        fn authenticate<'a>(
            &'a mut self,
            state: &'a mut Self::State,
            action_id: &'a str,
            message: &'a str,
            icon_name: &'a str,
            details: HashMap<&'a str, &'a str>,
            cookie: &'a str,
            identifies: Vec<Identity<'a>>,
        ) -> impl Future<Output = Result<(), Error>> + Send {
            self.authenticate.authenticate(
                state, action_id, message, icon_name, details, cookie, identifies,
            )
        }

        fn cancel_authentication<'a>(
            &'a mut self,
            state: &'a mut State,
            cookie: &'a str,
        ) -> impl Future<Output = Result<(), Error>> + Send {
            self.cancel_authentication
                .cancel_authentication(state, cookie)
        }
    }
    PolkitAgentBuilder {
        agent: Instance {
            boot: Some(boot),
            authenticate,
            cancel_authentication,
            _state: PhantomData,
        },
    }
}

fn locale() -> String {
    std::env::var("LANG").unwrap_or("en_US.UTF-8".to_owned())
}

impl<State, C: PolkitCore<State = State> + 'static> PolkitAgentBuilder<C>
where
    State: 'static + Send + Sync,
{
    pub async fn connect(
        mut self,
        object_path: impl Into<Option<&str>>,
    ) -> Result<zbus::Connection, error::Error> {
        let agent = PolkitAgent {
            state: self.agent.boot(),
            agent: self.agent,
        };
        let object_path = object_path
            .into()
            .unwrap_or("/org/freedesktop/PolicyKit1/AuthenticationAgent");
        let conn = connection::Builder::system()?
            .serve_at(object_path, agent)?
            .build()
            .await?;

        let session = UnixSession::new()?;
        let auth = AuthorityProxy::builder(&conn).build().await?;
        auth.register_authentication_agent(&session.into(), &locale(), object_path)
            .await?;

        Ok(conn)
    }
}
