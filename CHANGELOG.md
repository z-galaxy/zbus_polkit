# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 7.0.0 - 2026-11-21

### ✨ Added
- Be an authentication agent, with the new agent feature, on by default: policykit1::agent::Agent
  serves the AuthenticationAgent interface, and hands each of the daemon's requests to a Handler,
  as a Request that borrows its text and (de)serializes. #111
- Add AuthenticationAgentProxy, to call an agent as the daemon does. It takes the details as a
  Request holds them, and fails with policykit1::Error.
- Add policykit1::Error, polkit's org.freedesktop.PolicyKit1.Error domain, which a zbus::Error
  converts into: a mechanism whose methods return it passes polkit's errors on under their names.
- Add Subject::new_for_unix_session.
- Add accessors for the details of each kind of Subject.
- Add Subject::try_clone, to copy a subject.
- Make ActionDescription and AuthorizationResult Clone, PartialEq and Eq, and ImplicitAuthorization
  Clone and Hash.

### 💥 Breaking
- Make Identity typed and decodable, with a constructor and an accessor for each kind of identity
  in place of its public fields.
- Let Subject borrow its text and pidfd, with a lifetime. Subject::new_for_owner takes anything
  that converts into a zbus Fd, and no longer fails. #131
- Take the uid of a process Subject as the i32 that polkit reads.
- Hold the text of polkit's replies as Str, for services to borrow: TemporaryAuthorization,
  ActionDescription and AuthorizationResult take a lifetime, 'static where AuthorityProxy returns
  them.
- Make ImplicitAuthorization Copy. A closure that takes one by value now borrows it unless it is a
  move closure, so one that outlives the value needs move.
- Return the authority's backend name and version as Box<str>, not String.
- Remove the BadSender variant of zbus_polkit::Error, which nothing returns.

### 👷 CI
- Add a workflow to release with release-plz.

### 📦 Dependencies
- Require zbus 6.5, whose fdo::Error passes polkit's errors on under their names too, and whose
  Str decodes strings that it can't borrow.
- Require zcheapstr 1.4, to look Str keys up by &str.

## 6.0.0 - 2026-10-20

### 💥 Breaking
- Make AuthorityFeatures a bitflags type.
- Make CheckAuthorizationFlags a bitflags type.
- Pass a pidfd from Subject::new_for_owner. #103
- Rename the PID-based Subject::new_for_owner to Subject::new_for_pid.
- Hide the fields of Subject. Its kind is available through Subject::kind.
- Drop AuthorityProxyBlocking and the blocking-api feature, since zbus 6 has no blocking API.
- Port to zbus 6, where zbus::zvariant::Value is now zbus::Variant. This changes the type of
  Identity::identity_details and of the options argument of
  AuthorityProxy::register_authentication_agent_with_options.
- Raise the MSRV to 1.89.

### 👷 CI
- Install polkit in the test jobs.
- Sync renovate config with zbus.
- Add semver-checks job.
- Add doc build job.
- Test every feature combination.
- Run clippy on stable across the feature matrix.
- Add MSRV job and declare the real minimum Rust version.
- Pass --locked to all cargo invocations.
- Align CI workflow layout with zbus.
- Enforce gimoji commit messages.

### ♻️ Changed
- Move Subject into its own module.
- Split /proc parsing out of the file reads.
- Add git hook scripts from zbus.
- Add codespell config.
- Add .editorconfig.
- Add rustfmt config matching zbus.
- Configure release-plz.

### 📦 Dependencies
- Use zbus 6.0.0 from crates.io.
- Update tokio to v1.53.3.
- Update zbus to its latest git main.
- Update serde_json to v1.0.154 (#116).
- Update serde_json to v1.0.152 (#115).
- Update zbus to its latest git main.
- Drop the enumflags2 dependency.
- Add the bitflags dependency.
- Update tokio to v1.53.2 (#112).
- Bump MSRV to match with the new zbus MSRV.
- Add rustix as a dev-dependency.
- Add serde_json as a dev-dependency.
- Depend on zbus git main and bump to 6.0.0.

### 📝 Documentation
- Show a pidfd in the README example.
- Document the Authority test backends.
- Document the git hook scripts.
- Add pull request template.
- Add security policy.
- Point CI badge at zbus_polkit.
- Add contribution guide.

### 🐛 Fixed
- Name the /proc field that was missing.

### ⚙️ Other
- 👽️ Update to latest zbus.
- ✏️ Fix typo in RegisterAuthenticationAgentWithOptions docs.

### ✅ Testing
- Drive AuthorityProxy against real or mock polkit.
- Test system-bus-name subjects from message headers.
- Test polkit wire signatures and enum encoding.
- Test unix-process subjects and /proc parsing.
