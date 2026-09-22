//! The details of a `unix-process` subject.

use zbus::{DeserializeDict, OwnedFd, SerializeDict, Type};

/// The details of a `unix-process` subject.
///
/// polkit accepts a process in two forms, and looks up in `/proc` whatever it is not given:
///
/// * a `pidfd` and a `uid`, which is what [`Subject::new_for_owner`](super::Subject::new_for_owner)
///   sends, or
///
/// * a `pid`, a `start-time` and a `uid`, which is what
///   [`Subject::new_for_pid`](super::Subject::new_for_pid) sends.
///
/// polkit itself may send any combination back, e.g. in a temporary authorization, which is why
/// none of these is required here.
#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zbus(signature = "a{sv}")]
pub(super) struct UnixProcess {
    /// A pidfd naming one specific incarnation of the process.
    ///
    /// polkit only trusts this when `uid` is sent with it, and then reads the process from it
    /// rather than from `pid` and `start_time`.
    pub(super) pidfd: Option<OwnedFd>,

    /// The process ID.
    ///
    /// A PID can be reused once the process it named exits, so `start_time` is what makes this
    /// name specific.
    pub(super) pid: Option<u32>,

    /// The start time of `pid`, in clock ticks since boot, as in field 22 of `/proc/<pid>/stat`.
    #[zbus(rename = "start-time")]
    pub(super) start_time: Option<u64>,

    /// The (real, not effective) uid of the owner of the process.
    ///
    /// polkit reads this as a *signed* 32-bit integer, which is why this is an `i32` and not a
    /// `u32`. Sent as any other type it is silently ignored and polkit falls back to its own racy
    /// `/proc` lookup.
    pub(super) uid: Option<i32>,
}
