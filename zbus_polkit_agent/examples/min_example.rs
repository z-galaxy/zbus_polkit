use std::collections::HashMap;

use rpassword::prompt_password;
use zbus_polkit_agent::{
    Identity, UnixUser,
    agent_session::{Message, PolkitAgentSession, Response},
    polkit_agent_instance,
    server::Error,
};
struct Agent;

fn authenticate(
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
            let message = session.dispatch()?;
            if let Message::Request { prompt, .. } = message {
                let Ok(password) = prompt_password(format!("{} {prompt} ", session.user_name()))
                else {
                    return Err(Error::Cancelled);
                };
                session.response(Response {
                    password: &password,
                })?;
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

fn cancel_authentication(_agent: &mut Agent, _cookie: &str) -> Result<(), Error> {
    Ok(())
}
const OBJECT_PATH: &str = "/org/waycrate/PolicyKit1/AuthenticationAgent";

#[tokio::main]
async fn main() {
    let _connection = polkit_agent_instance(|| Agent, authenticate, cancel_authentication)
        .connect(OBJECT_PATH)
        .await
        .unwrap();
    std::future::pending::<()>().await;
}
