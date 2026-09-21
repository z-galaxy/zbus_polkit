//! The `Subject` a polkit authority is asked about, and how it is sent and received.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;
use zbus::{names::OwnedUniqueName, OwnedValue, Type};

use crate::Error;

/// This struct describes subjects such as UNIX processes. It is typically used to check if a given
/// process is authorized for an action.
///
/// The following kinds of subjects are known:
///
/// * Unix Process. `subject_kind` should be set to `unix-process` with keys `pid` (of type
///   `uint32`) and `start-time` (of type `uint64`).
///
/// * Unix Session. `subject_kind` should be set to `unix-session` with the key `session-id` (of
///   type `string`).
///
/// * System Bus Name. `subject_kind` should be set to `system-bus-name` with the key `name` (of
///   type `string`).
#[derive(Debug, Type, Serialize, Deserialize)]
pub struct Subject {
    /// The type of the subject.
    pub subject_kind: String,

    /// Details about the subject. Depending of the value of `subject_kind`, a set of well-defined
    /// key/value pairs are guaranteed to be available.
    pub subject_details: HashMap<String, OwnedValue>,
}

assert_impl_all!(Subject: Send, Sync, Unpin);

impl Subject {
    /// Create a `Subject` for `pid`, `start_time` & `uid`.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process ID
    ///
    /// * `start_time` - The start time for `pid` or `None` to look it up in e.g. `/proc`
    ///
    /// * `uid` - The (real, not effective) uid of the owner of `pid` or `None` to look it up in
    ///   e.g. `/proc`
    pub fn new_for_owner(
        pid: u32,
        start_time: Option<u64>,
        uid: Option<u32>,
    ) -> Result<Self, Error> {
        let start_time = match start_time {
            Some(s) => s,
            None => pid_start_time(pid)?,
        };
        let uid = match uid {
            Some(u) => u,
            None => pid_uid_racy(pid)?,
        };
        let mut hashmap = HashMap::new();
        hashmap.insert("pid".to_string(), pid.into());
        hashmap.insert("start-time".to_string(), start_time.into());
        hashmap.insert("uid".to_string(), (uid as i32).into());

        Ok(Self {
            subject_kind: "unix-process".into(),
            subject_details: hashmap,
        })
    }

    /// Create a `Subject` for a message for querying if the sender of a Message is permitted to
    /// execute an action.
    ///
    /// # Arguments
    ///
    /// * `message_header` - The header of the message which caused an authentication to be
    ///   necessary.
    pub fn new_for_message_header(
        message_header: &zbus::message::Header<'_>,
    ) -> Result<Self, Error> {
        let mut subject_details = HashMap::new();
        match message_header.sender() {
            Some(sender) => {
                subject_details.insert(
                    "name".to_string(),
                    OwnedUniqueName::from(sender.clone()).try_into().unwrap(),
                );
            }
            None => {
                return Err(Error::MissingSender);
            }
        }

        Ok(Self {
            subject_kind: "system-bus-name".to_string(),
            subject_details,
        })
    }
}

fn pid_start_time(pid: u32) -> Result<u64, Error> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_start_time(&stat)
}

// Extract the process start time (field 22 of proc(5) `stat`, in clock ticks since boot).
//
// The second field, `comm`, is the executable name wrapped in parentheses and may itself contain
// spaces and parentheses, so fields are counted from the *last* closing parenthesis rather than
// from the start of the line.
fn parse_start_time(stat: &str) -> Result<u64, Error> {
    let start_time = stat
        .rfind(')')
        .and_then(|i| stat[i..].split(' ').nth(20))
        .ok_or(Error::MalformedSlashProc("start-time"))?;

    Ok(start_time.parse()?)
}

// Return the "current" UID.  Note that this is inherently racy, and the value may already be
// obsolete by the time this function returns; this function only guarantees that the UID was valid
// at some point during its execution.
fn pid_uid_racy(pid: u32) -> Result<u32, Error> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    parse_uid(&status)
}

// Extract the real UID from the contents of proc(5) `status`.
//
// The `Uid:` line lists the real, effective, saved set and filesystem UIDs; only the first one is
// returned, since that is what polkit expects in a `unix-process` subject.
fn parse_uid(status: &str) -> Result<u32, Error> {
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().next())
        .ok_or(Error::MalformedSlashProc("uid"))?;

    Ok(uid.parse()?)
}

#[cfg(test)]
mod tests {
    use zbus::{message::Message, Value};

    use super::*;

    #[test]
    fn subject_for_owner_uses_polkit_wire_types() {
        let subject = Subject::new_for_owner(4242, Some(1_000_000), Some(1234)).unwrap();

        assert_eq!(subject.subject_kind, "unix-process");
        assert_eq!(subject.subject_details.len(), 3);
        assert_eq!(*subject.subject_details["pid"], Value::U32(4242));
        assert_eq!(
            *subject.subject_details["start-time"],
            Value::U64(1_000_000)
        );
        // polkit reads `uid` as a signed 32-bit integer. Sent as any other type it is silently
        // ignored and polkit falls back to its own racy /proc lookup, which defeats the purpose
        // of passing a UID obtained from a trusted source (see #101).
        assert_eq!(*subject.subject_details["uid"], Value::I32(1234));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subject_for_owner_looks_up_the_process_in_proc() {
        use std::os::unix::fs::MetadataExt;

        let pid = std::process::id();
        let subject = Subject::new_for_owner(pid, None, None).unwrap();

        // /proc/<pid> is owned by the process's UID, which gives us an independent source of
        // truth that doesn't go through the parser under test.
        let uid = std::fs::metadata("/proc/self").unwrap().uid();
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let start_time = parse_start_time(&stat).unwrap();

        assert_eq!(*subject.subject_details["pid"], Value::U32(pid));
        assert_eq!(*subject.subject_details["uid"], Value::I32(uid as i32));
        assert_eq!(
            *subject.subject_details["start-time"],
            Value::U64(start_time)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subject_for_owner_fails_for_a_missing_process() {
        // pid_max is capped at 2^22 on Linux, so this PID can never exist.
        let err = Subject::new_for_owner(u32::MAX, None, None).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err:?}");
    }

    #[test]
    fn start_time_is_field_22_counted_from_the_last_paren() {
        // proc(5): pid, (comm), state, ppid, pgrp, session, tty_nr, tpgid, flags, minflt,
        // cminflt, majflt, cmajflt, utime, stime, cutime, cstime, priority, nice, num_threads,
        // itrealvalue, starttime, vsize, rss, ...
        let stat = "1 (systemd) S 0 1 1 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 42 12345678 100\n";
        assert_eq!(parse_start_time(stat).unwrap(), 42);

        // `comm` is not escaped, so a process name containing spaces and parentheses shifts
        // every naive field count. Counting from the last `)` is what makes this work.
        let stat = "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 \
                    0 987654 12345678 100\n";
        assert_eq!(parse_start_time(stat).unwrap(), 987654);
    }

    #[test]
    fn start_time_rejects_malformed_stat() {
        assert!(matches!(
            parse_start_time(""),
            Err(Error::MalformedSlashProc("start-time"))
        ));
        assert!(matches!(
            parse_start_time("no parens here"),
            Err(Error::MalformedSlashProc("start-time"))
        ));
        // Too few fields after `comm`.
        assert!(matches!(
            parse_start_time("1234 (x) S 1 1234"),
            Err(Error::MalformedSlashProc("start-time"))
        ));
        // Field 22 present but not a number.
        let stat = "1 (x) S 0 1 1 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 forty-two 12345678 100";
        assert!(matches!(parse_start_time(stat), Err(Error::ParseInt(_))));
    }

    #[test]
    fn uid_is_the_real_uid_from_status() {
        let status = "Name:\tmy proc\n\
                      Umask:\t0022\n\
                      State:\tS (sleeping)\n\
                      Tgid:\t1234\n\
                      Pid:\t1234\n\
                      PPid:\t1\n\
                      TracerPid:\t0\n\
                      Uid:\t1000\t1001\t1002\t1003\n\
                      Gid:\t2000\t2001\t2002\t2003\n";
        // Real UID, not effective (1001) or saved-set (1002).
        assert_eq!(parse_uid(status).unwrap(), 1000);
    }

    #[test]
    fn uid_rejects_malformed_status() {
        assert!(matches!(
            parse_uid(""),
            Err(Error::MalformedSlashProc("uid"))
        ));
        assert!(matches!(
            parse_uid("Name:\tx\nGid:\t0\t0\t0\t0\n"),
            Err(Error::MalformedSlashProc("uid"))
        ));
        assert!(matches!(
            parse_uid("Uid:\n"),
            Err(Error::MalformedSlashProc("uid"))
        ));
        assert!(matches!(
            parse_uid("Uid:\tnobody\n"),
            Err(Error::ParseInt(_))
        ));
    }

    // Signature as documented in the polkit D-Bus API reference:
    // https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html
    #[test]
    fn wire_signatures_match_polkit() {
        assert_eq!(Subject::SIGNATURE.to_string(), "(sa{sv})");
    }

    #[test]
    fn subject_for_message_header_uses_the_sender_bus_name() {
        let msg = Message::method_call("/org/example/Object", "Frobnicate")
            .sender(":1.42")
            .build(&())
            .unwrap();

        let subject = Subject::new_for_message_header(&msg.header()).unwrap();

        assert_eq!(subject.subject_kind, "system-bus-name");
        assert_eq!(subject.subject_details.len(), 1);
        assert_eq!(*subject.subject_details["name"], Value::Str(":1.42".into()));
    }

    #[test]
    fn subject_for_message_header_requires_a_sender() {
        let msg = Message::method_call("/org/example/Object", "Frobnicate")
            .build(&())
            .unwrap();

        let err = Subject::new_for_message_header(&msg.header()).unwrap_err();
        assert!(matches!(err, Error::MissingSender), "{err:?}");
    }
}
