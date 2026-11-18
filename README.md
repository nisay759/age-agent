# age-agent

Caches unlocked age identities in a background daemon and exposes them to age clients
(`age`, `rage`, passage, sops…) as a plugin. See `docs/SPEC.md`.

```sh
cargo install --path .                      # installs age-agent and age-plugin-agent
age-agent setup ~/.passage/identities       # once: writes ~/.config/age-agent/identities.txt
export PASSAGE_IDENTITIES_FILE=~/.config/age-agent/identities.txt
passage show web/shop/example.com           # first use prompts, later uses don't
age-agent status [--json]                   # exit 0 unlocked, 1 locked, 2 no daemon
age-agent lock                              # wipe now
```

Optional systemd user unit: `contrib/age-agent.service`. On sway/i3, call `age-agent lock`
from your idle/lock hook; the daemon only auto-locks on D-Bus signals (logind, ScreenSaver).
The socket lives under `$XDG_RUNTIME_DIR`, which must be set (it is in any logind or systemd
user session); there is deliberately no `/tmp` fallback.

## Windows

Same commands; the config lives in `%APPDATA%\age-agent\` and the agent listens on
`\\.\pipe\age-agent-<your SID>`. `setup --print-env` prints the Git Bash and PowerShell lines.

- With no terminal, the plugin asks through the native Windows credential dialog. Set
  `prompt.pinentry` to an absolute path (e.g. Gpg4win's `pinentry.exe`) to use a pinentry
  instead, or `prompt.mode = "native"` to always use the dialog.
- The daemon locks on session lock, user switch and suspend, and wipes and exits on log-off.
- Same-user processes cannot read the daemon's memory, and `taskkill`/`Stop-Process` are
  refused too. Use `age-agent stop`.
- Optional start at logon: `contrib\install-logon-task.ps1` (the plugin starts it on demand anyway).
- `AGE_AGENT_INSTANCE=<name>` runs a separate agent (used by the tests).

## Tests

`cargo test` runs everything for the current platform (it also builds the `examples/` the
Windows tests use). On Windows, `AGE_AGENT_TEST_CLIENT=<path to age.exe>` runs the integration
tests through the official `age` client instead of the `age` crate.

## Auditing

`cargo audit` runs against `Cargo.lock`; `.cargo/audit.toml` lists the advisories that are
known not to be reachable from this code, each with the reason.

## Fuzzing

Needs nightly and `cargo install cargo-fuzz`. Targets: `frame` (socket message parser) and
`stub` (stub decoder). Seeds live in `fuzz/corpus/<target>/`.

```sh
cd fuzz
cargo +nightly fuzz run frame -- -max_total_time=300 -max_len=70000
cargo +nightly fuzz run stub  -- -max_total_time=300
```

## Status

- Linux complete (M1, M2), tested against `age`, `rage` and `passage`.
- Windows (M3): named pipe with SID and squatting checks, native credential prompt, session-lock,
  suspend and log-off auto-lock, detached auto-start. Tested on Windows 11 against `age` 1.3.2
  and the `age` crate's plugin client.
- Not yet implemented: macOS, mlkem768x25519, confirm-each-use, logging, CI.

The design is in `docs/SPEC.md`.
