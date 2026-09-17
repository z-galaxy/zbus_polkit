//! The `Subject` a polkit authority is asked about, and how it is sent and received.

mod system_bus_name;
mod unix_process;
mod unix_session;

use std::{collections::HashMap, os::fd::AsFd};

use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;
use zbus::{names::OwnedUniqueName, OwnedValue, Type};

use self::{system_bus_name::SystemBusName, unix_process::UnixProcess, unix_session::UnixSession};
use crate::Error;

/// This struct describes subjects such as UNIX processes. It is typically used to check if a given
/// process is authorized for an action.
///
/// On the wire a subject is a kind string and a dictionary of details whose contents depend on that
/// kind. The constructors here build the kinds polkit documents. A subject of a kind this crate
/// does not know about, or whose details are not the ones it expects, is kept as it arrived, so a
/// newer polkit stays readable.
#[derive(Debug, Type, Serialize, Deserialize)]
#[zbus(signature = "(sa{sv})")]
#[serde(transparent)]
pub struct Subject(Kind);

assert_impl_all!(Subject: Send, Sync, Unpin);

impl Subject {
    /// The kind this subject is sent as, e.g. `unix-process`.
    pub fn kind(&self) -> &str {
        match &self.0 {
            Kind::UnixProcess(_) => UNIX_PROCESS,
            Kind::UnixSession(_) => UNIX_SESSION,
            Kind::SystemBusName(_) => SYSTEM_BUS_NAME,
            Kind::Other(raw) => &raw.subject_kind,
        }
    }

    /// Create a `Subject` for a process identified by `pidfd`.
    ///
    /// A pidfd names a specific process incarnation, so this is not subject to the PID-reuse
    /// race that [`new_for_pid`](Self::new_for_pid) is. Polkit requires `uid` to be sent
    /// together with a pidfd and will not look it up itself; obtain both from a trusted source
    /// at the same time (e.g. `SO_PEERPIDFD` and `SO_PEERCRED`, or `pidfd_open` and a known
    /// uid).
    ///
    /// # Arguments
    ///
    /// * `pidfd` - A pidfd for the process (from `pidfd_open(2)` or `SO_PEERPIDFD`)
    ///
    /// * `uid` - The (real, not effective) uid of the owner of the process
    pub fn new_for_owner(pidfd: impl AsFd, uid: u32) -> Result<Self, Error> {
        Ok(Self(Kind::UnixProcess(UnixProcess {
            pidfd: Some(pidfd.as_fd().try_clone_to_owned()?.into()),
            pid: None,
            start_time: None,
            uid: Some(uid as i32),
        })))
    }

    /// Create a `Subject` for `pid`, `start_time` & `uid`.
    ///
    /// A PID can be reused after the original process exits, so this form is racy. Prefer
    /// [`new_for_owner`](Self::new_for_owner) when the kernel and polkit support pidfds.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process ID
    ///
    /// * `start_time` - The start time for `pid` or `None` to look it up in e.g. `/proc`
    ///
    /// * `uid` - The (real, not effective) uid of the owner of `pid` or `None` to look it up in
    ///   e.g. `/proc`
    pub fn new_for_pid(pid: u32, start_time: Option<u64>, uid: Option<u32>) -> Result<Self, Error> {
        let start_time = match start_time {
            Some(s) => s,
            None => pid_start_time(pid)?,
        };
        let uid = match uid {
            Some(u) => u,
            None => pid_uid_racy(pid)?,
        };

        Ok(Self(Kind::UnixProcess(UnixProcess {
            pidfd: None,
            pid: Some(pid),
            start_time: Some(start_time),
            uid: Some(uid as i32),
        })))
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
        let sender = message_header.sender().ok_or(Error::MissingSender)?;

        Ok(Self(Kind::SystemBusName(SystemBusName {
            name: OwnedUniqueName::from(sender.clone()),
        })))
    }
}

/// The kinds of subject polkit documents, each with its details, and whatever else arrived.
///
/// Adjacent tagging is the `(kind, details)` pair polkit reads: a struct of two fields, which
/// D-Bus sends as a sequence and a self-describing format as a map, in either order. Serde only
/// knows how to read the details once it has the kind, and does the buffering that takes itself.
#[derive(Debug, Type, Serialize, Deserialize)]
#[zbus(signature = "(sa{sv})")]
#[serde(tag = "subject_kind", content = "subject_details")]
enum Kind {
    #[serde(rename = "unix-process")]
    UnixProcess(UnixProcess),

    #[serde(rename = "unix-session")]
    UnixSession(UnixSession),

    #[serde(rename = "system-bus-name")]
    SystemBusName(SystemBusName),

    /// Tried once none of the above matched, so its kind is either one this crate has no struct
    /// for or a known one whose details did not decode. Both are kept as they arrived: the caller
    /// still sees the kind, and nothing polkit sent is lost.
    #[serde(untagged)]
    Other(Raw),
}

/// A subject as it is on the wire, for a kind this crate has no struct for.
#[derive(Debug, Type, Serialize, Deserialize)]
struct Raw {
    subject_kind: String,
    subject_details: HashMap<String, OwnedValue>,
}

const UNIX_PROCESS: &str = "unix-process";
const UNIX_SESSION: &str = "unix-session";
const SYSTEM_BUS_NAME: &str = "system-bus-name";

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
    use zbus::{
        message::Message,
        wire::{serialized::Context, to_bytes, LE},
        Value,
    };

    use super::*;
    use crate::policykit1::TemporaryAuthorization;

    /// The `(kind, details)` pair `subject` is sent as, read back off the wire.
    fn sent_as(subject: &Subject) -> (String, HashMap<String, OwnedValue>) {
        let encoded = to_bytes(Context::new(LE, 0), subject).expect("serialize the subject");

        encoded
            .deserialize()
            .expect("decode the subject as the types polkit reads")
            .0
    }

    /// A `Subject` decoded from the `(kind, details)` pair an authority would send, if it decodes.
    fn receive<const N: usize>(
        kind: &str,
        details: [(&str, Value<'_>); N],
    ) -> zbus::Result<Subject> {
        let details: HashMap<String, OwnedValue> = details
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.try_into().unwrap()))
            .collect();
        let encoded =
            to_bytes(Context::new(LE, 0), &(kind.to_string(), details)).expect("serialize details");

        encoded.deserialize().map(|(subject, _)| subject)
    }

    /// A `Subject` decoded from the `(kind, details)` pair an authority would send.
    fn received_as<const N: usize>(kind: &str, details: [(&str, Value<'_>); N]) -> Subject {
        receive(kind, details).expect("decode a subject")
    }

    #[cfg(unix)]
    #[test]
    fn subject_for_owner_sends_pidfd_and_uid() {
        // What is on the other end of the descriptor does not matter here: `new_for_owner` takes
        // any `AsFd`, and what is under test is how it is sent, not what polkit makes of it.
        let pidfd = std::fs::File::open("/dev/null").unwrap();
        let subject = Subject::new_for_owner(&pidfd, 1234).unwrap();

        assert_eq!(subject.kind(), "unix-process");
        let Kind::UnixProcess(details) = &subject.0 else {
            panic!("expected a unix-process subject, got {subject:?}");
        };
        assert!(details.pidfd.is_some());
        assert_eq!(details.uid, Some(1234));
        // A pidfd names one incarnation of the process, so polkit needs neither of these, and
        // ignores them when a pidfd is there.
        assert_eq!(details.pid, None);
        assert_eq!(details.start_time, None);

        let (kind, sent) = sent_as(&subject);

        assert_eq!(kind, "unix-process");
        assert_eq!(sent.len(), 2);
        // A UNIX_FD ('h'), not a raw i32: polkit looks the handle up in the message's fd list.
        // Sent as any other type it is ignored and polkit falls back to pid+start-time.
        assert_eq!(sent["pidfd"].value_signature().to_string(), "h");
        // polkit refuses a pidfd subject without a uid, and ignores a uid that is not i32.
        assert_eq!(*sent["uid"], Value::I32(1234));
    }

    #[test]
    fn subject_for_pid_uses_polkit_wire_types() {
        let subject = Subject::new_for_pid(4242, Some(1_000_000), Some(1234)).unwrap();
        let (kind, sent) = sent_as(&subject);

        assert_eq!(kind, "unix-process");
        // A pidfd is absent rather than sent as an empty value, so polkit reads the process from
        // the fields below.
        assert_eq!(sent.len(), 3);
        assert_eq!(*sent["pid"], Value::U32(4242));
        assert_eq!(*sent["start-time"], Value::U64(1_000_000));
        // polkit reads `uid` as a signed 32-bit integer. Sent as any other type it is silently
        // ignored and polkit falls back to its own racy /proc lookup, which defeats the purpose
        // of passing a UID obtained from a trusted source (see #101).
        assert_eq!(*sent["uid"], Value::I32(1234));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subject_for_pid_looks_up_the_process_in_proc() {
        use std::os::unix::fs::MetadataExt;

        let pid = std::process::id();
        let subject = Subject::new_for_pid(pid, None, None).unwrap();

        // /proc/<pid> is owned by the process's UID, which gives us an independent source of
        // truth that doesn't go through the parser under test.
        let uid = std::fs::metadata("/proc/self").unwrap().uid();
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let start_time = parse_start_time(&stat).unwrap();

        let Kind::UnixProcess(details) = &subject.0 else {
            panic!("expected a unix-process subject, got {subject:?}");
        };
        assert_eq!(details.pid, Some(pid));
        assert_eq!(details.uid, Some(uid as i32));
        assert_eq!(details.start_time, Some(start_time));
    }

    #[test]
    fn subject_decodes_the_details_of_the_kind_it_was_sent_as() {
        // What polkit puts in a temporary authorization: no pidfd, and on older versions no uid
        // either, so a missing key cannot be an error. A key this crate does not know about cannot
        // be one either, or a future polkit would stop being readable.
        let process = received_as(
            "unix-process",
            [
                ("pid", Value::U32(4242)),
                ("start-time", Value::U64(7)),
                ("something-new", Value::from("ignore me")),
            ],
        );
        assert_eq!(process.kind(), "unix-process");
        let Kind::UnixProcess(details) = &process.0 else {
            panic!("expected a unix-process subject, got {process:?}");
        };
        assert_eq!(details.pid, Some(4242));
        assert_eq!(details.start_time, Some(7));
        assert_eq!(details.uid, None);
        assert!(details.pidfd.is_none());

        let session = received_as("unix-session", [("session-id", Value::from("c2"))]);
        assert_eq!(session.kind(), "unix-session");
        let Kind::UnixSession(details) = &session.0 else {
            panic!("expected a unix-session subject, got {session:?}");
        };
        assert_eq!(details.session_id, "c2");

        let bus_name = received_as("system-bus-name", [("name", Value::from(":1.42"))]);
        assert_eq!(bus_name.kind(), "system-bus-name");
        let Kind::SystemBusName(details) = &bus_name.0 else {
            panic!("expected a system-bus-name subject, got {bus_name:?}");
        };
        assert_eq!(details.name.as_str(), ":1.42");
    }

    #[test]
    fn subject_keeps_a_kind_it_does_not_know_as_it_arrived() {
        let subject = received_as("unix-netgroup", [("name", Value::from("engineering"))]);

        assert_eq!(subject.kind(), "unix-netgroup");
        let Kind::Other(raw) = &subject.0 else {
            panic!("expected an unknown kind to be kept, got {subject:?}");
        };
        assert_eq!(*raw.subject_details["name"], Value::from("engineering"));

        // And it goes back out as it came in.
        let (kind, sent) = sent_as(&subject);
        assert_eq!(kind, "unix-netgroup");
        assert_eq!(*sent["name"], Value::from("engineering"));
    }

    // Serde falls back to `Kind::Other` whenever no tagged variant decoded, so a known kind whose
    // details are not what this crate expects lands there too. It is kept rather than refused: the
    // caller still sees the kind, and nothing polkit sent is lost.
    #[test]
    fn subject_keeps_a_known_kind_whose_details_do_not_decode() {
        let subject = received_as("unix-process", [("pid", Value::from("not a pid"))]);

        assert_eq!(subject.kind(), "unix-process");
        let Kind::Other(raw) = &subject.0 else {
            panic!("expected the subject to be kept as it arrived, got {subject:?}");
        };
        assert_eq!(*raw.subject_details["pid"], Value::from("not a pid"));
    }

    // D-Bus sends the `(kind, details)` pair as a sequence, a self-describing format as a map, and
    // `serde_json::to_value` sorts the keys of that map, which puts the details before the kind.
    // All of it has to decode, or a `Subject` cannot be read back out of anything it was written
    // to. `from_str` hands strings over borrowed and `from_value` owned, so both are tried.
    #[test]
    fn subject_round_trips_through_a_self_describing_format() {
        let session = received_as("unix-session", [("session-id", Value::from("c2"))]);
        for back in [
            serde_json::from_str::<Subject>(&serde_json::to_string(&session).unwrap()).unwrap(),
            serde_json::from_value::<Subject>(serde_json::to_value(&session).unwrap()).unwrap(),
        ] {
            let Kind::UnixSession(details) = back.0 else {
                panic!("decoded as another kind");
            };
            assert_eq!(details.session_id, "c2");
        }

        // Integer widths survive too: `pid` comes back the `u32` it left as, not the format's
        // widest integer.
        let process = Subject::new_for_pid(4242, Some(1_000_000), Some(1234)).unwrap();
        for back in [
            serde_json::from_str::<Subject>(&serde_json::to_string(&process).unwrap()).unwrap(),
            serde_json::from_value::<Subject>(serde_json::to_value(&process).unwrap()).unwrap(),
        ] {
            let Kind::UnixProcess(details) = back.0 else {
                panic!("decoded as another kind");
            };
            assert_eq!(details.pid, Some(4242));
            assert_eq!(details.start_time, Some(1_000_000));
            assert_eq!(details.uid, Some(1234));
            assert!(details.pidfd.is_none());
        }

        // And enclosed in something the derive handles, since that is how one usually arrives.
        let authorization = TemporaryAuthorization {
            id: "x".into(),
            action_id: "a".into(),
            subject: session,
            time_obtained: 1,
            time_expires: 2,
        };
        for back in [
            serde_json::from_str::<TemporaryAuthorization>(
                &serde_json::to_string(&authorization).unwrap(),
            )
            .unwrap(),
            serde_json::from_value::<TemporaryAuthorization>(
                serde_json::to_value(&authorization).unwrap(),
            )
            .unwrap(),
        ] {
            assert_eq!(back.id, "x");
            assert_eq!(back.subject.kind(), "unix-session");
        }
    }

    // An unknown kind's details decode as `OwnedValue`s, whose map visitor reads its field names
    // (`signature` and `value`) borrowed. A borrowed input, `from_str`, decodes them; an owned
    // one, `from_value`, can only do so while there are no details to read.
    #[test]
    fn subject_of_an_unknown_kind_round_trips_through_a_self_describing_format() {
        let subject = received_as("brand-new-kind", [("k", Value::from("v"))]);
        let json = serde_json::to_string(&subject).unwrap();
        let back: Subject = serde_json::from_str(&json).unwrap();

        assert_eq!(back.kind(), "brand-new-kind");
        let Kind::Other(raw) = &back.0 else {
            panic!("decoded as a known kind");
        };
        assert_eq!(*raw.subject_details["k"], Value::from("v"));

        // What `serde_json::to_value` lays the keys out as: the details first.
        let reversed = r#"{"subject_details":{"k":{"signature":"s","value":"v"}},"subject_kind":"brand-new-kind"}"#;
        let back: Subject = serde_json::from_str(reversed).unwrap();

        assert_eq!(back.kind(), "brand-new-kind");
        let Kind::Other(raw) = &back.0 else {
            panic!("decoded as a known kind");
        };
        assert_eq!(*raw.subject_details["k"], Value::from("v"));

        let subject = received_as("brand-new-kind", []);
        let back: Subject =
            serde_json::from_value(serde_json::to_value(&subject).unwrap()).unwrap();
        assert_eq!(back.kind(), "brand-new-kind");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subject_for_pid_fails_for_a_missing_process() {
        // pid_max is capped at 2^22 on Linux, so this PID can never exist.
        let err = Subject::new_for_pid(u32::MAX, None, None).unwrap_err();
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
            Err(Error::MalformedSlashProc(_))
        ));
        assert!(matches!(
            parse_start_time("no parens here"),
            Err(Error::MalformedSlashProc(_))
        ));
        // Too few fields after `comm`.
        assert!(matches!(
            parse_start_time("1234 (x) S 1 1234"),
            Err(Error::MalformedSlashProc(_))
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
        assert!(matches!(parse_uid(""), Err(Error::MalformedSlashProc(_))));
        assert!(matches!(
            parse_uid("Name:\tx\nGid:\t0\t0\t0\t0\n"),
            Err(Error::MalformedSlashProc(_))
        ));
        assert!(matches!(
            parse_uid("Uid:\n"),
            Err(Error::MalformedSlashProc(_))
        ));
        assert!(matches!(
            parse_uid("Uid:\tnobody\n"),
            Err(Error::ParseInt(_))
        ));
    }

    // Signatures as documented in the polkit D-Bus API reference:
    // https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html
    #[test]
    fn wire_signatures_match_polkit() {
        assert_eq!(Subject::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(Kind::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(Raw::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(UnixProcess::SIGNATURE.to_string(), "a{sv}");
        assert_eq!(UnixSession::SIGNATURE.to_string(), "a{sv}");
        assert_eq!(SystemBusName::SIGNATURE.to_string(), "a{sv}");
    }

    #[test]
    fn subject_for_message_header_uses_the_sender_bus_name() {
        let msg = Message::method_call("/org/example/Object", "Frobnicate")
            .sender(":1.42")
            .build(&())
            .unwrap();

        let subject = Subject::new_for_message_header(&msg.header()).unwrap();

        assert_eq!(subject.kind(), "system-bus-name");
        let Kind::SystemBusName(details) = &subject.0 else {
            panic!("expected a system-bus-name subject, got {subject:?}");
        };
        assert_eq!(details.name.as_str(), ":1.42");

        let (kind, sent) = sent_as(&subject);

        assert_eq!(kind, "system-bus-name");
        assert_eq!(sent.len(), 1);
        assert_eq!(*sent["name"], Value::Str(":1.42".into()));
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
