use std::collections::HashMap;

use rpassword::prompt_password;
use zbus_polkit::{
    identify::{Identity, UnixUser},
    polkitagent::{
        agent_session::{Message, PolkitAgentSession, Response},
        polkit_agent_instance,
        server::Error,
    },
};

struct UnSyncAbleValue;

#[allow(unused)]
struct Agent {
    moved_value: UnSyncAbleValue,
}

async fn authenticate(
    _agent: &mut Agent,
    _action_id: &str,
    _msg: &str,
    _icon_name: &str,
    _details: HashMap<&str, &str>,
    cookie: &str,
    mut identifiers: Vec<Identity<'_>>,
) -> Result<(), Error> {
    let identify: UnixUser = identifiers.remove(0).try_into()?;
    let mut session = PolkitAgentSession::new(identify, cookie)?;
    let mut retry_count = 3;
    while retry_count >= 0 {
        while !session.is_complete() {
            let message = session.async_dispatch().await?;
            match message {
                Message::Error(error) => {
                    // maybe what happened to polkit?
                    println!("error: {error}");
                }
                Message::Info(info) => {
                    // often tell you what happened to this account,
                    // for example
                    // The account is locked due to 3 failed logins.
                    // (10 minutes left to unlock)
                    println!("info: {info}");
                }
                Message::Request { prompt, .. } => {
                    let Ok(password) =
                        prompt_password(format!("{} {prompt} ", session.user_name()))
                    else {
                        return Err(Error::Cancelled);
                    };
                    session.response(Response {
                        password: &password,
                    })?;
                }
                _ => {}
            }
        }

        if session.succeeded() {
            return Ok(());
        }
        session.restart()?;
        retry_count -= 1;
    }
    if !session.succeeded() {
        return Err(Error::Failed);
    }
    Ok(())
}

async fn cancel_authentication(_agent: &mut Agent, _cookie: &str) -> Result<(), Error> {
    Ok(())
}
const OBJECT_PATH: &str = "/org/waycrate/PolicyKit1/AuthenticationAgent";

#[tokio::main]
async fn main() {
    let moved_value = UnSyncAbleValue;
    let _connection = polkit_agent_instance(
        move || Agent { moved_value },
        authenticate,
        cancel_authentication,
    )
    .connect(OBJECT_PATH)
    .await
    .unwrap();
    std::future::pending::<()>().await;
}
