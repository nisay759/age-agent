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
- Not yet implemented: Windows, macOS, mlkem768x25519, confirm-each-use, logging, CI.

The design is in `docs/SPEC.md`.
