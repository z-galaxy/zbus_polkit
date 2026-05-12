use std::collections::HashMap;

use zbus::zvariant::OwnedValue;
use zbus_polkit::policykit1::Subject;

#[derive(Debug, Clone)]
pub struct UnixSession {
    pub session_id: String,
}

impl UnixSession {
    pub fn new() -> Result<Self, crate::error::Error> {
        let id = nix::unistd::getpid();

        let session_id = systemd::login::get_session(Some(id.as_raw()))?;

        Ok(Self { session_id })
    }
}

impl From<UnixSession> for Subject {
    fn from(val: UnixSession) -> Self {
        let session_id = OwnedValue::from(zbus::zvariant::Str::from(val.session_id.as_str()));
        Subject {
            subject_kind: "unix-session".to_string(),
            subject_details: HashMap::from_iter([("session-id".to_string(), session_id)]),
        }
    }
}
