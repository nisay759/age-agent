# age-agent — SPEC

## Overview

age-agent caches unlocked age identities in a background process, so passage, rofi-passage and the GUI ask for the passphrase once per session instead of once per decryption. It is an age **plugin** backed by a daemon: clients keep calling `age -d`, and the private key never leaves the daemon's memory.

**Goals**

- One passphrase prompt per session (or per timeout) for any age client that supports plugins: `age`, `rage`, passage, sops, and any app built on the age libraries.
- No change to passage or to the store: existing `.age` files and `age1…` recipients keep working, so PassPony and other devices are unaffected.
- The private key is never written to disk in plaintext, and clients get file keys back, not the identity.
- Linux and Windows required, macOS supported.
- Small and auditable: target under 2,000 lines of Rust for the daemon, plugin and CLI together.

**Non-goals**

- Hardware-backed keys. YubiKey or TPM users already have plugins for that; age-agent caches software identities only.
- Encryption. Encrypting to `age1…` recipients needs no secret, so it stays with the client.
- A general secrets store or password cache. The agent holds age identities and nothing else.
- Network access or remote forwarding.

**How passage uses it, unchanged**

```sh
age-agent setup ~/.passage/identities        # once: writes the plugin identity file
export PASSAGE_IDENTITIES_FILE=~/.config/age-agent/identities.txt
passage show web/shop/example.com            # first use prompts, later uses don't
```

## Architecture

Two programs from one codebase: a long-running **daemon** that holds unlocked identities, and a short-lived **plugin** that age launches on every decryption. The [age plugin spec](https://github.com/C2SP/C2SP/blob/main/age-plugin.md) lets a plugin unwrap native `X25519` and `mlkem768x25519` stanzas, so files encrypted to ordinary `age1…` recipients work as is.

&#91;embedded content: age-agent · decryption path and control path\]

Clients only ever receive per-file keys; the encrypted identity is read once per unlock and its key stays inside the daemon.

| Component | Binary | Lifetime | Role |
| --- | --- | --- | --- |
| Daemon | `age-agent daemon` | Session (auto-started, exits on logout) | Holds decrypted identities in locked memory, enforces timeouts and lock events, unwraps stanzas on request |
| Plugin | `age-plugin-agent` | One decryption | Speaks the age plugin protocol on stdio, forwards stanzas to the daemon, returns file keys to age |
| CLI | `age-agent` | One command | `setup`, `unlock`, `lock`, `status`, `daemon`, `stop` |
| Encrypted identity | e.g. `~/.passage/identities` | Permanent | The at-rest source of truth: a passphrase-encrypted age identity file. Unchanged, and still usable directly if age-agent is removed |
| Plugin identity file | `~/.config/age-agent/identities.txt` | Permanent | Contains only `AGE-PLUGIN-AGENT-1…` stubs. Holds no secret, so it can be world-readable |

**Decryption flow**

1. A client runs `age -d -i ~/.config/age-agent/identities.txt entry.age`.
2. age finds an `AGE-PLUGIN-AGENT-1…` identity and starts `age-plugin-agent --age-plugin=identity-v1`, then sends it every recipient stanza in the file header.
3. The plugin connects to the daemon's socket, starting the daemon first if none is running, and forwards the `X25519` and `mlkem768x25519` stanzas with the identity reference from the stub.
4. If the daemon is locked, the plugin gets the passphrase (see UNL-2) and sends `unlock`. The daemon decrypts the at-rest identity file and keeps the identities in memory.
5. The daemon unwraps the matching stanza and returns the 16-byte file key. The plugin replies `file-key` to age, which decrypts the payload.

**Why a plugin and not a decrypted key file in RAM**

|  | Decrypted key file in `/run/user` | Plugin + daemon (chosen) |
| --- | --- | --- |
| What a same-user process gets while unlocked | The private key itself, usable forever after | File keys for files it asks about, only while unlocked |
| Effect of a lock or timeout | Future reads fail; copies already taken stay valid | Nothing usable remains |
| Client changes | `PASSAGE_IDENTITIES_FILE` must switch between two files | One static identities file, no client changes |
| Works for other age clients | Yes, by pointing them at the file | Yes, through the plugin protocol |

The plugin model matches ssh-agent and gpg-agent: while unlocked, any process running as the user can still ask for decryptions. It cannot walk away with the key.

## Functional requirements

Must items make the first release; Should items follow in 1.x; Could items wait for demand.

| ID | Requirement | Priority |
| --- | --- | --- |
| SET-1 | `age-agent setup <identity-file>…` asks the passphrase once, derives each identity's public recipient, and writes one `AGE-PLUGIN-AGENT-1…` stub per identity to `~/.config/age-agent/identities.txt`, each preceded by a `# recipient: age1…` comment | Must |
| SET-2 | Setup records the mapping "stub reference → identity file" in `~/.config/age-agent/config.toml`. It never modifies or copies the at-rest identity file | Must |
| SET-3 | Several identity files, and several identities per file, are supported | Must |
| SET-4 | `age-agent setup --print-env` prints the shell lines to add, e.g. `export PASSAGE_IDENTITIES_FILE=…` | Should |
| UNL-1 | `age-agent unlock [--timeout DURATION]` prompts on the terminal and loads every configured identity file | Must |
| UNL-2 | When a decryption arrives while locked, the plugin prompts on demand: first through age's `request-secret`, which age answers from the terminal or refuses at once when there is none, then through a pinentry program (Assuan `GETPIN`, configurable, `pinentry` by default). Concurrent decryptions share one prompt | Must |
| UNL-3 | GUI clients can unlock over the socket with a passphrase they collected in their own dialog (`unlock` request) | Must |
| UNL-4 | A wrong passphrase allows 3 attempts per unlock request, then fails with a clear error. No persistent lockout | Must |
| UNL-5 | Windows: when no pinentry is configured, the plugin uses the native credential prompt (`CredUIPromptForWindowsCredentialsW`) | Should |
| LCK-1 | `age-agent lock` wipes all identities immediately and cancels any pending prompt | Must |
| LCK-2 | Idle timeout since last unwrap, default 15 min (`0` = none), plus a maximum unlocked lifetime, default 8 h | Must |
| LCK-3 | Auto-lock on screen lock and on suspend or hibernate (see Platform support). `mlock` does not keep pages out of the hibernation image, so on Linux the daemon holds a logind *delay* inhibitor for sleep: the wipe is guaranteed to finish before the system sleeps, and the inhibitor is released right after it and taken again on resume | Must on Linux and Windows, Should on macOS |
| LCK-4 | Daemon exit (stop, logout, crash handler) zeroizes identities first | Must |
| STA-1 | `age-agent status` prints locked/unlocked, loaded recipients and time left; `--json` for rofi-passage and the GUI. Exit code 0 unlocked, 1 locked, 2 no daemon | Must |
| DEC-1 | Unwrap `X25519` and `mlkem768x25519` stanzas with loaded identities (mlkem768x25519 is Should: only once the Rust age crate supports post-quantum identities); ignore unknown stanza types and report malformed known ones, as the plugin spec requires | Must |
| DEC-2 | Only identities named by the stubs passed to `add-identity` are tried, so a client's identity file selects which identities serve it. This is scoping, not authorization: a reference is a hash of the public recipient and `status` lists every loaded recipient, so any same-user client can name any loaded identity (see the threat model) | Must |
| DEC-3 | The socket returns file keys only. No request exports an identity or a passphrase | Must |
| DEC-4 | Optional confirm-each-use mode, like `ssh-add -c`: every unwrap request shows a pinentry confirm naming the requesting program | Could |
| DMN-1 | The plugin auto-starts the daemon (detached, same user) when the socket is absent; a systemd user unit and a Windows logon task are provided as alternatives | Must |
| DMN-2 | One daemon per user session; a second instance exits with a clear message | Must |
| LOG-1 | Optional local log of unlocks, locks and unwraps (time, requesting PID and executable path, stanza count), never secrets. age does not tell plugins which file is being decrypted | Should |

## Security requirements and threat model

The agent narrows what a same-user attacker can take from "the key" to "decryptions while unlocked". It does not defend against root, an administrator, or a keylogger that captures the passphrase.

| Attacker | Outcome with age-agent |
| --- | --- |
| Steals the disk or a backup | Gets the scrypt-encrypted identity file only. No plaintext key is ever written, including to swap or crash dumps |
| Same-user process, agent locked or timed out | Nothing to take: identities are wiped from memory |
| Same-user process, agent unlocked | Can request unwraps through the socket, as with ssh-agent. Cannot extract the identity. Mitigated by timeouts, auto-lock, DEC-4 and LOG-1 |
| Another local user | Cannot reach the socket (permissions and peer-credential check) and cannot impersonate the daemon (squatting checks) |
| Reads the plugin identity file | Learns only recipient references, which are public |
| Root, administrator, kernel-level malware, keylogger | Out of scope |

| ID | Requirement |
| --- | --- |
| SEC-1 | Identities live in locked memory (`mlock` / `VirtualLock` on their allocation) and are zeroized on lock, timeout and exit (`zeroize` + `secrecy` crates). The allocation is sized once and never grown, shrunk or moved, since a reallocation would leave an unzeroized copy outside the locked region; the stack used while parsing is scrubbed afterwards. Transient plaintext, such as the decrypted identity file while it is parsed, is zeroized but not locked. `mlockall` is not used: it breaks thread creation under the default `RLIMIT_MEMLOCK`. `status` reports `memory_locked` so a daemon that could not lock memory is noticed |
| SEC-2 | Core dumps and crash dumps are disabled where the OS allows (`PR_SET_DUMPABLE 0` and `RLIMIT_CORE 0` on Linux) for all three programs: the daemon holds the identities, the plugin holds the passphrase it collects and the file keys, and the CLI holds the passphrase (`unlock`) or the decrypted identity (`setup`) |
| SEC-3 | The passphrase is never accepted through argv, environment variables or files. It is zeroized right after the scrypt work |
| SEC-4 | Linux and macOS socket: `$XDG_RUNTIME_DIR/age-agent/agent.sock` (macOS: per-user temp dir), parent dir `0700`. On Linux there is no fallback when `XDG_RUNTIME_DIR` is unset: a directory under the shared `/tmp` could be created first by another user, who could then keep the agent from starting. The daemon checks the peer UID (`SO_PEERCRED` / `getpeereid`) on every connection |
| SEC-5 | Windows pipe: `\\.\pipe\age-agent-<user SID>`, created with `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`, DACL limited to the user's SID. The daemon checks the client process token; the client checks the server process owner before sending anything |
| SEC-6 | Socket protocol: length-prefixed messages, 64 KiB maximum, a version field, strict parsing, unknown requests rejected |
| SEC-7 | No network sockets and no outbound connections, ever |
| SEC-8 | The pinentry program comes from the config file as an absolute path, never from the client's environment. When unset, only fixed system paths are searched (`/usr/bin/pinentry`, `/usr/local/bin/pinentry`, `/opt/homebrew/bin/pinentry`, `/usr/bin/pinentry-mac`), never `PATH` |
| SEC-9 | `unsafe` code only for the OS calls in SEC-1, SEC-2, SEC-4 and SEC-5, isolated in one module with tests |
| SEC-10 | Minimal dependencies, `cargo-deny` and `cargo-audit` in CI (policy in `.cargo/audit.toml`, every ignored advisory with its reachability argument), reproducible release builds, signed release artifacts and checksums |

## Interfaces

Three contracts are public and versioned: the CLI, the plugin identity format and the socket protocol. rofi-passage and the GUI depend on the last one, so it changes only with a version bump.

**Client contract: age-agent is always optional**

No client may require age-agent. Each keeps its own safe unlock path (rofi-passage: a per-run pinentry unlock held in a sealed memfd; the GUI: its own dialog and in-memory identity), and age-agent only replaces that path when present.

| Situation | How a client detects it | What the client does |
| --- | --- | --- |
| Not installed | `age-agent` not on `PATH` | Its own fallback, no warning beyond an optional hint |
| Installed, daemon not running | `age-agent status --json` exits 2 | `age-agent unlock` (which starts the daemon), or its own fallback |
| Locked | Exit 1 | `age-agent unlock` through pinentry or the socket |
| Unlocked | Exit 0 | Decrypt through the stub identities file |
| Stub file in use but `age-plugin-agent` missing | The identities file holds `AGE-PLUGIN-AGENT-1…` lines and the plugin is not on `PATH` | Report it with the fix (point `PASSAGE_IDENTITIES_FILE` back to the encrypted file) instead of age's raw "plugin not found" error |

`status` never starts the daemon, so probing is free of side effects. Because setup never touches the encrypted identity file, uninstalling age-agent loses nothing.

**CLI**

| Command | Effect |
| --- | --- |
| `age-agent setup [--force] <identity-file>…` | SET-1 to SET-3; refuses to overwrite an existing stub file without `--force` |
| `age-agent unlock [--timeout 15m]` | Terminal prompt, loads every configured identity file |
| `age-agent lock` | Wipe now |
| `age-agent status [--json]` | STA-1 |
| `age-agent daemon [--foreground]` | Start the daemon; `--foreground` for systemd and debugging |
| `age-agent stop` | Lock, then exit the daemon |
| `age-plugin-agent` | Run by age clients only, never by hand |

**Plugin identity format**

Bech32 with the HRP `AGE-PLUGIN-AGENT-`, as the plugin spec requires. The payload is a version byte (`0x01`) followed by a 16-byte reference: the first 16 bytes of SHA-256 over the recipient string. The stub names an identity without containing it.

```text
# recipient: age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq
AGE-PLUGIN-AGENT-1Q9JX…
```

**Socket protocol, version 1**

Each message is a 4-byte big-endian length followed by a JSON object; binary fields are base64. A connection starts with `hello` and the daemon answers every request with exactly one response.

| Request | Fields | Response |
| --- | --- | --- |
| `hello` | `version` | `version`, `daemon_version` |
| `status` | — | `locked`, `recipients[]`, `idle_left_s`, `lifetime_left_s`, `epoch`, `prompting`, `memory_locked` |
| `unlock` | `passphrase`, `timeout_s`?, `epoch`? | `ok`, or error `bad_passphrase` / `no_identities` / `cancelled` |
| `lock` | — | `ok` |
| `stop` | — | `ok`, then the daemon locks and exits |
| `unwrap` | `refs[]`, `stanzas[]` of `{type, args[], body}` for one file | `file_key`, or error `locked` / `no_match` / `malformed` |
| `claim` | — | `ok`, or error `busy`. Grants the right to show the unlock prompt until this connection closes |
| `wait` | `epoch`, `timeout_s`? (max 300) | `{changed, locked, epoch}` once the epoch moves past `epoch`, at the timeout, or, on a connection without the claim, once nobody holds it |

Errors share one shape: `{"error": {"code": "locked", "message": "…"}}`. Besides the codes above, any request can fail with `version`, `bad_request` or `internal`. The plugin sends one `unwrap` per file index it received from age.

**Lock epoch.** The daemon keeps a counter that every lock and every unlock increments; `lock` increments it even when already locked. `status` reports it and `prompting` says whether someone holds the claim. An `unlock` that carries an `epoch` fails with `cancelled` if the counter has moved since, so a passphrase typed before a lock cannot undo that lock.

**Prompt coordination (LCK-1, UNL-2).** A plugin that finds the agent locked opens a second connection and sends `claim`. The winner shows the prompt and blocks on that second connection in `wait`; when the epoch moves (an `age-agent lock`, or an unlock by someone else such as the GUI), it kills the pinentry and either decrypts (agent now unlocked) or fails with "unlock cancelled by `age-agent lock`". The losers `wait` instead and decrypt once the agent unlocks, or try to claim again if the prompting client gave up. Prompts that cannot be killed (age's own terminal prompt through `request-secret`, the CLI's `age-agent unlock`) are covered by sending the starting `epoch` with `unlock`.

**Config file** (`~/.config/age-agent/config.toml`, `%APPDATA%\age-agent\config.toml` on Windows)

```toml
[[identity]]
file = "~/.passage/identities"
refs = ["5d1c…"]          # written by setup

[agent]
idle_timeout = "15m"      # 0 = no idle timeout
max_lifetime = "8h"
lock_on_screen_lock = true
lock_on_suspend = true
confirm_each_use = false  # DEC-4
log = false               # LOG-1

[prompt]
mode = "auto"             # auto | terminal | pinentry | native
pinentry = "/usr/bin/pinentry-gnome3"
```

## Platform support

Linux and Windows are release blockers; macOS ships when its row passes the acceptance tests.

|  | Linux | Windows 10/11 | macOS |
| --- | --- | --- | --- |
| Transport | Unix socket in `$XDG_RUNTIME_DIR` | Named pipe (SEC-5) | Unix socket in the per-user temp dir |
| Peer check | `SO_PEERCRED` | Client token SID; server owner SID | `getpeereid` |
| Memory locking | `mlock`, `PR_SET_DUMPABLE 0` | `VirtualLock` | `mlock` |
| Screen-lock auto-lock | logind `Lock` signal and `LockedHint`, plus `org.freedesktop.ScreenSaver` / `org.gnome.ScreenSaver` `ActiveChanged` | `WTSRegisterSessionNotification` → `WTS_SESSION_LOCK` | `com.apple.screenIsLocked` distributed notification |
| Suspend auto-lock | logind `PrepareForSleep`, with a `delay` sleep inhibitor | `WM_POWERBROADCAST` / `PBT_APMSUSPEND` | `NSWorkspaceWillSleepNotification` |
| Start | Auto-start by the plugin, or the shipped systemd user unit | Auto-start by the plugin (detached, no console window), or a logon task | Auto-start, or the shipped launchd agent |
| Prompt when no terminal | pinentry (gnome3, qt, gtk) | Native credential prompt (UNL-5) or Gpg4win's pinentry | pinentry-mac |

Notes:

- Window managers without a logind-aware locker (sway, i3) call `age-agent lock` from their idle or lock hook, e.g. swayidle's `before-sleep` and `lock` commands. The README documents this.
- WSL is a separate Linux session with its own agent. Windows-side clients (the GUI, Git Bash with Windows `age.exe`) share the Windows agent, and WSL clients share a WSL agent; the two never mix.
- Every client must use an age implementation with plugin support: `age` 1.1 or newer, `rage`, or the Go and Rust age libraries.

## Stack, testing and acceptance

Rust for everything, so the daemon, plugin and CLI share one crate and one audit, and the GUI can reuse the client library.

| Need | Choice |
| --- | --- |
| Language | Rust stable, edition 2024; two binaries (`age-agent`, `age-plugin-agent`) from one workspace |
| age primitives | [`age`](https://docs.rs/age) crate: scrypt-encrypted identity files, `x25519::Identity` stanza unwrapping |
| Plugin protocol | [`age-plugin`](https://docs.rs/age-plugin) 0.7: `IdentityPluginV1` (`add_identity`, `unwrap_file_keys`) and its `request_secret` / `confirm` callbacks |
| Concurrency | OS threads and blocking I/O, one thread per connection; no async runtime of our own |
| Secrets in memory | `secrecy`, `zeroize`; direct `mlock` / `VirtualLock` calls |
| Lock events | `zbus` (logind, ScreenSaver) on Linux; `windows` crate (WTS, power, CredUI, pipe security) on Windows; `objc2` on macOS. zbus 6 has no blocking API and pulls in tokio (~20 crates); a hand-written D-Bus match would remove them |
| Other | `serde_json`, `toml`, `bech32`, `sha2`, `clap` |

**Tests**

- Unit: stub encoding round trip, protocol parser, timeout logic on a mocked clock.
- Fuzz: `cargo-fuzz` on the socket message parser and the stub decoder.
- Integration, on Linux, Windows and macOS CI runners: encrypt to a test recipient, then decrypt through `age -d -i <stubs>` with the agent unlocked, locked (fake pinentry answering), and after `lock`. Repeat with `rage` and `passage show`.
- Security: a second OS user cannot connect (Linux container test); a pre-created pipe with the same name is detected (Windows); core dumps are off (on Linux, checked by another same-user process failing to open `/proc/<pid>/mem`, since `/proc/<pid>` ownership does not reliably reflect `PR_SET_DUMPABLE`); no file under the user's home or runtime dir ever contains the identity (filesystem watch during the integration suite); after an unlock exactly one copy of the raw key exists in writable memory and after a lock none does (a `/proc/self/mem` scan of the daemon's loading path); the sleep inhibitor is held, released after the wipe and retaken on resume (fake logind).

**Acceptance criteria for 1.0**

- [ ] With the agent unlocked, 100 consecutive `passage show` calls trigger no prompt; with it locked, the first call prompts once and the other 99 do not.
- [ ] After `age-agent lock`, the idle timeout, a screen lock (GNOME, KDE, Windows 11) or a suspend, `status` reports locked within 1 second and the next decryption prompts.
- [ ] From rofi (no terminal), a locked agent prompts through pinentry; on Windows, through the native prompt.
- [ ] Uninstalling age-agent and pointing `PASSAGE_IDENTITIES_FILE` back at the encrypted file restores normal passage behaviour, with no store change.
- [ ] The security tests above pass on all three CI platforms.

## Milestones and open questions

Linux first, because that is where every assumption below gets validated; Windows is the second release blocker.

1. **M1 — Linux prototype:** plugin, daemon, terminal unlock, idle timeout, X25519 unwrap. Answers open questions 1 and 3.
2. **M2 — Linux complete:** pinentry fallback, logind and screensaver auto-lock, `status --json`, systemd user unit, security tests.
3. **M3 — Windows:** named pipe with SID and squatting checks, native credential prompt, session-lock and suspend auto-lock, detached auto-start.
4. **M4 — 1.0:** fuzzing in CI, documentation, signed reproducible releases, packages (crates.io, AUR, Scoop or winget).
5. **M5 — macOS:** launchd agent, pinentry-mac, lock notifications.

**Open questions**

- [x] When the client has no terminal (rofi, a GUI), does `request-secret` fail fast in `age`, `rage` and the Go library, so the plugin can fall back to pinentry, or does it hang? **Answer:** it fails fast: `age` 1.2.1 and `rage` 0.12.1 refuse in under 0.1 s (`tests/clients.rs`), and the Go library behaves like the age CLI built on it. No detection rule is needed: in `mode = "auto"` the plugin always tries `request-secret` first and falls back to pinentry; `terminal` and `pinentry` force one path.
- [ ] When does the Rust `age` crate support `mlkem768x25519` identities? Until then, post-quantum identities are not cached.
- [x] While one client waits on an unlock prompt, should other clients' requests queue behind it or fail with `locked`? **Answer:** they queue, through `claim` and `wait` (see Prompt coordination). Six concurrent decryptions produce one prompt.
- [ ] Is the `age-plugin-agent` name free on crates.io and in the age plugin ecosystem?
- [ ] Should `setup` also offer to re-encrypt the identity file with a new passphrase, or stay strictly read-only (current choice: read-only)?

**Later versions to explore: hardware-bound device identities**

A device's key could be created inside its TPM ([age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm)) or Secure Enclave (age-plugin-se) and added to `.age-recipients` as an `age1tag1…` recipient, a type age 1.3.0 encrypts to natively. Decryption then happens in hardware and the private key never exists in memory, so there is nothing for age-agent to cache. Clients reach these identities through their existing plugin path: rofi-passage's plugin mode and the GUI's IDN-2.

To answer before adopting it:

- [ ] Can every writer encrypt to `age1tag1…` recipients: the age CLI (yes from 1.3.0), the Rust `age` crate used by the GUI, and PassPony's age engine? A writer that cannot would save entries the hardware-bound device cannot read.
- [ ] Does age-plugin-tpm run on Windows, and does age-plugin-se cover macOS well enough?
- [ ] Recovery: a TPM-bound key is lost with the motherboard or a TPM clear, so the passphrase-protected software identity stays a recipient, backed up offline.
- [ ] PIN prompts: the TPM plugin asks for its PIN on every decryption (its `AGE_TPM_PIN` variable is insecure by its own README). age-agent could cache that PIN, which is useless away from the machine's TPM; worth a design note if this path is adopted.
