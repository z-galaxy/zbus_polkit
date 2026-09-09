# Contributing to zbus_polkit

We welcome contributions from everyone in the form of suggestions, bug reports, pull requests, and
feedback. This document gives some guidance if you are thinking of helping us.

Please reach out here in a Github issue, or in the [#zbus:matrix.org][matrix-room] Matrix room if we
can do anything to help you contribute.

## Submitting bug reports and feature requests

You can create issues [here][new-issue]. When reporting a bug or asking for help, please include
enough details so that the people helping you can reproduce the behavior you are seeing. For some
tips on how to approach this, read about how to produce a [Minimal, Complete, and Verifiable
Example][mcve].

When making a feature request, please make it clear what problem you intend to solve with the
feature, any ideas for how the crate in question could support solving that problem, any possible
alternatives, and any disadvantages.

## Submitting Pull Requests

Same rules apply here as for bug reports and feature requests. Plus:

- We prefer atomic commits. Please read [this excellent blog post][atomic-commits] for more
  information, including the rationale. For larger changes, consider splitting your pull request
  into a series of focused commits.
- Please try your best to follow [these guidelines][commit-messages] for commit messages.
- We also prefer adding emoji prefixes to commit messages. You can either use [`gimoji`][gimoji] CLI
  tool (which can be installed as a commit hook) or pick one directly from [here][gimoji-list]
  (please remember to copy the emoji itself and not the `:emoji-code:` string, by just clicking on
  it). **NOTE:** This is a curated list of emojis that have specific meanings. Please use one of the
  methods recommended here to select/fetch the most appropriate one. 🙏
- Add details to each commit about the changes it contains. PR description is for summarizing the
  overall changes in the PR, while commit logs are for describing the specific changes of the commit
  in question.
- When addressing review comments, fix the existing commits in the PR (rather than adding additional
  commits) and force push (as in `git push -f`) to your branch. You may find
  [`git-absorb`][git-absorb] and [`git-revise`][git-revise] extremely useful, especially if you're
  not very familiar with interactive rebasing and modifying commits in git.

### Code layout

Within a module, order items top-down, as described in [rustls' contribution guide][rustls-layout]:
items depend on items defined _below_ them, not above. In practice: the public API sits near the top
of the file, private helpers below the code that calls them, simple `const`s below their users, and
`#[cfg(test)] mod tests` at the very bottom.

### Legal Notice

When contributing to this project, you **implicitly** declare that:

- you have authored 100% of the content,
- you have the necessary rights to the content, and
- you agree to providing the content under the [project's license](LICENSE).

## Running the test suite

We encourage you to check that the test suite passes locally before submitting a pull request with
your changes. If anything does not pass, typically it will be easier to iterate and fix it locally
than waiting for the CI servers to run tests for you.

```sh
# Run the full test suite, including doc tests.
cargo test --all-features
```

The `Authority` tests in `tests/authority.rs` talk to the polkit daemon when one is answering on
the system bus, and to an in-process mock of the same interface when there is none. Set
`ZBUS_POLKIT_MOCK` to use the mock even where a daemon is running, and `ZBUS_POLKIT_REQUIRE_REAL`
to turn a missing daemon into a failure rather than a fallback. CI sets both, in separate runs, so
that each backend is covered.

Also please ensure that code is formatted correctly by running:

```sh
cargo +nightly fmt --all
```

and clippy doesn't see anything wrong with the code:

```sh
cargo clippy -- -D warnings
```

Please note that there are times when clippy is wrong and you know what you are doing. In such
cases, it's acceptable to tell clippy to [ignore the specific error or warning in the
code][clippy-allow].

If you intend to contribute often or think that's very likely, we recommend installing the commit
hook provided by [`gimoji`][gimoji], as well as the git hook scripts contained within this
repository, which run `rustfmt` before each commit and `clippy` before each push. You can enable
them with:

```sh
cp .githooks/* .git/hooks/
```

The two do not conflict: `gimoji` installs a `prepare-commit-msg` hook, while the scripts here are
`pre-commit` and `pre-push` hooks.

## Conduct

In all zbus-related forums, we follow the [Rust Code of Conduct][rust-code-of-conduct]. For
escalation or moderation issues please contact Zeeshan (zeeshanak@gnome.org) instead of the Rust
moderation team.

[atomic-commits]: https://www.aleksandrhovhannisyan.com/blog/atomic-git-commits/
[clippy-allow]: https://github.com/rust-lang/rust-clippy#allowingdenying-lints
[commit-messages]: https://handbook.gnome.org/development/commit-messages.html
[gimoji]: https://github.com/zeenix/gimoji
[gimoji-list]: https://zeenix.github.io/gimoji/
[git-absorb]: https://github.com/tummychow/git-absorb
[git-revise]: https://github.com/mystor/git-revise
[matrix-room]: https://matrix.to/#/#zbus:matrix.org
[mcve]: https://stackoverflow.com/help/mcve
[new-issue]: https://github.com/z-galaxy/zbus_polkit/issues/new
[rust-code-of-conduct]: https://www.rust-lang.org/conduct.html
[rustls-layout]: https://github.com/rustls/rustls/blob/main/CONTRIBUTING.md
