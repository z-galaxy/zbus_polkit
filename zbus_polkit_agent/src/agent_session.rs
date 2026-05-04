use crate::error::Error;
use nix::unistd::{Uid, User};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
};

const POLKIT_AGENT_HELPER_SOCKET: &str = "/run/polkit/agent-helper.socket";

#[derive(Debug)]
pub struct PolkitAgentSession {
    user: User,
    stream: UnixStream,
    complete: bool,
    succeeded: bool,
    cached_cookie: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Message {
    Request { echo_on: bool, prompt: String },
    Error(String),
    Info(String),
    Complete(bool),
}

/// Response the password
#[derive(Debug)]
pub struct Response<'a> {
    pub password: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub enum Status {
    Succeeded,
    Failure,
    Running,
}

const PAM_PROMPT_ECHO_OFF: &str = "PAM_PROMPT_ECHO_OFF";
const PAM_PROMPT_ECHO_ON: &str = "PAM_PROMPT_ECHO_ON";
const PAM_ERROR_MSG: &str = "PAM_ERROR_MSG";
const PAM_TEXT_INFO: &str = "PAM_TEXT_INFO";
const SUCCESS: &str = "SUCCESS";
const FAILURE: &str = "FAILURE";

impl PolkitAgentSession {
    pub fn user_name(&self) -> &str {
        self.user.name.as_ref()
    }
    pub fn new<'a>(uid: impl Into<Uid>, cookie: impl Into<Option<&'a str>>) -> Result<Self, Error> {
        let uid = uid.into();
        let mut cached_cookie = None;
        let user = nix::unistd::User::from_uid(uid)?.ok_or(Error::UserNotFound(uid.as_raw()))?;

        let agent_path = Path::new(POLKIT_AGENT_HELPER_SOCKET);
        if !agent_path.exists() {
            return Err(Error::PolkitFileNotFound);
        }

        let mut stream = UnixStream::connect(agent_path)?;
        stream.write_all(user.name.as_bytes())?;
        stream.write_all(b"\n")?;

        if let Some(cookie) = cookie.into() {
            stream.write_all(cookie.as_bytes())?;
            stream.write_all(b"\n")?;
            cached_cookie = Some(cookie.to_owned());
        }

        Ok(Self {
            user,
            stream,
            cached_cookie,
            complete: false,
            succeeded: false,
        })
    }

    pub fn restart(&mut self) -> Result<(), Error> {
        // reconnect
        let stream = UnixStream::connect(POLKIT_AGENT_HELPER_SOCKET)?;
        self.stream = stream;
        self.stream.write_all(self.user.name.as_bytes())?;
        self.stream.write_all(b"\n")?;

        if let Some(cookie) = self.cached_cookie.as_ref() {
            self.stream.write_all(cookie.as_bytes())?;
            self.stream.write_all(b"\n")?;
        }
        self.complete = false;
        self.succeeded = false;
        Ok(())
    }

    #[inline]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    #[inline]
    pub fn succeeded(&self) -> bool {
        matches!(self.status(), Status::Succeeded)
    }
    pub fn status(&self) -> Status {
        if !self.complete {
            return Status::Running;
        }
        if self.succeeded {
            Status::Succeeded
        } else {
            Status::Failure
        }
    }

    pub fn dispatch(&mut self) -> Result<Message, Error> {
        if self.complete {
            return Ok(Message::Complete(self.succeeded));
        }
        let mut data = vec![];
        loop {
            let mut exact = [0; 1];
            self.stream.read_exact(&mut exact)?;

            if exact[0] == b'\n' {
                data.extend(exact);
                break;
            }
            data.extend(exact);
        }
        let response = String::from_utf8_lossy(&data);
        if let Some(stripped) = response.strip_prefix(PAM_PROMPT_ECHO_OFF) {
            let prompt = stripped.trim().to_string();
            return Ok(Message::Request {
                echo_on: false,
                prompt,
            });
        }
        if let Some(stripped) = response.strip_prefix(PAM_PROMPT_ECHO_ON) {
            let prompt = stripped.trim().to_string();
            return Ok(Message::Request {
                echo_on: true,
                prompt,
            });
        }

        if let Some(stripped) = response.strip_prefix(PAM_ERROR_MSG) {
            let message = stripped.trim_start().to_string();
            return Ok(Message::Error(message));
        }
        if let Some(stripped) = response.strip_prefix(PAM_TEXT_INFO) {
            let message = stripped.trim_start().to_string();
            return Ok(Message::Info(message));
        }

        self.complete = true;
        if response.starts_with(SUCCESS) {
            self.succeeded = true;
            return Ok(Message::Complete(true));
        }
        if response.starts_with(FAILURE) {
            return Ok(Message::Complete(false));
        }
        Err(Error::UnknownMessage(response.to_string()))
    }

    pub fn response<'a>(&mut self, Response { password }: Response<'a>) -> Result<(), Error> {
        self.stream.write_all(password.as_bytes())?;
        self.stream.write_all(b"\n")?;
        Ok(())
    }
}
