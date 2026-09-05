use libsystemd_sys::uid_t;
use nix::libc::{free, strlen};
use std::{
    collections::HashMap,
    ffi::{c_char, c_void},
    ptr,
};

use zbus::zvariant::OwnedValue;
use crate::policykit1::Subject;

/// a new UnixSession for a polkitagent
#[derive(Debug, Clone)]
pub struct UnixSession {
    pub session_id: String,
}

unsafe fn free_cstring(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let len = unsafe { strlen(ptr) };
    let char_slice = unsafe { std::slice::from_raw_parts(ptr as *mut u8, len) };
    let s = String::from_utf8_lossy(char_slice).into_owned();
    unsafe { free(ptr as *mut c_void) };
    Some(s)
}

pub fn get_display(uid: uid_t) -> Result<String, systemd::Error> {
    let mut c_session: *mut c_char = ptr::null_mut();
    systemd::ffi_result(unsafe { libsystemd_sys::login::sd_uid_get_display(uid, &mut c_session) })?;
    let ss = unsafe { free_cstring(c_session).unwrap() };
    Ok(ss)
}

impl UnixSession {
    pub fn new() -> Result<Self, crate::error::Error> {
        let id = nix::unistd::getpid();

        if let Ok(session_id) = systemd::login::get_session(Some(id.as_raw())) {
            return Ok(Self { session_id });
        }
        let uid = systemd::login::get_owner_uid(Some(id.as_raw()))?;
        let session_id = get_display(uid)?;

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
