# zbus_polkit

[![CI Pipeline Status](https://github.com/z-galaxy/zbus_polkit/actions/workflows/rust.yml/badge.svg)](https://github.com/z-galaxy/zbus_polkit/actions/workflows/rust.yml)
[![Documentation](https://docs.rs/zbus_polkit/badge.svg)](https://docs.rs/zbus_polkit/)
[![crates.io](https://img.shields.io/crates/v/zbus_polkit)](https://crates.io/crates/zbus_polkit)

A crate to interact with [PolicyKit], a toolkit for defining and handling authorizations. It is used
for allowing unprivileged processes to speak to privileged processes.

**Status:** Stable.

## Example code

```rust,no_run
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use zbus::Connection;
use zbus_polkit::policykit1::*;

// Although we use `tokio` here, you can use any async runtime of choice.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::system().await?;
    let proxy = AuthorityProxy::new(&connection).await?;
    // Prefer a pidfd (from pidfd_open or SO_PEERPIDFD) over a raw PID: PIDs get reused.
    // Polkit requires the uid to be sent with the pidfd; take it from a trusted source
    // (here, this process's own real uid).
    let pidfd = pidfd_open(
        Pid::from_raw(std::process::id() as i32).ok_or("pid 0")?,
        PidfdFlags::empty(),
    )?;
    let subject = Subject::new_for_owner(&pidfd, rustix::process::getuid().as_raw())?;
    let result = proxy.check_authorization(
        &subject,
        "org.zbus.BeAwesome",
        &std::collections::HashMap::new(),
        CheckAuthorizationFlags::AllowUserInteraction.into(),
        "",
    ).await?;

    Ok(())
}
```

[PolicyKit]: https://gitlab.freedesktop.org/polkit/polkit/
