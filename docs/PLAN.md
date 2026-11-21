# Synced SSH Client — Phase 1 Plan

Status: **awaiting approval**. No code has been written.
Date: 2026-11-21

Contents: [1 Pushback](#1-pushback-read-this-first) · [2 Architecture](#2-architecture) · [3 Packages](#3-packages) · [4 Data model](#4-data-model) · [5 Crypto](#5-crypto-design) · [6 Sync protocol](#6-sync-protocol) · [7 Server](#7-sync-server) · [8 Repo layout](#8-repo-layout) · [9 Phases](#9-phases) · [10 Testing](#10-testing) · [11 Decisions needed](#11-decisions-i-need-from-you)

---

## 1. Pushback (read this first)

Things in the spec I think are wrong, risky, or need a decision. Ordered by importance.

**1.1 Enrolling with "URL + code + master passphrase" means the server holds a brute-forceable copy of your vault key.**
For a new device to get the vault key from only a passphrase, the server must store the passphrase-wrapped key. A server compromise then allows unlimited offline guessing of the passphrase; Argon2id slows that down but a weak passphrase still falls. That contradicts principle 1 ("a full compromise must not expose a single credential").
*Recommendation:* add a 256-bit random **sync key** (like 1Password's Secret Key) generated on the first device. It never reaches the server. The wrapped vault key stored on the server is sealed under it. It travels to a new device inside the enrollment QR (so QR enrollment is still "scan, then type passphrase"); manual enrollment means typing URL + code + a 52-character sync key. Server compromise then yields nothing guessable. Cost: one more thing in your backup sheet. See §5.4.

**1.2 "Revoke a device" cannot un-share secrets.**
A revoked device loses server access but still holds the vault key and everything it had synced. Revocation is honest only as "stop future sync". The UI will say so and prompt you to rotate passwords/keys that device had. A revoked device that comes back online gets a `revoked` response and wipes its local vault, but that is cooperative, not enforceable. Vault-key rotation is listed under Later.

**1.3 Windows Hello is a gate, not a lock.**
`local_auth` on Windows returns a yes/no; DPAPI releases the stored key to any process running as your Windows user, with or without Hello. So on Windows, "biometric unlock" protects against someone at your unlocked keyboard, not against malware running as you. Android is properly bound: `flutter_secure_storage` 11.2 has Keystore-backed biometric-enforced options (`enforceBiometrics`, strong-biometric-only), which I'll verify on a device in Phase 3. I'll document the difference in the app rather than pretend they're equal.

**1.4 Wall-clock "last writer wins" breaks when a device clock is wrong.**
I'll use Hybrid Logical Clocks per field (wall time + counter + device ID) instead of raw timestamps. The server also returns its time on every response, and the Sync screen warns if a device is more than 5 minutes off.

**1.5 The server cannot merge, so field-level merge has to happen on the client.**
With whole-record encryption the server sees opaque blobs. Design: the server does optimistic concurrency per record (accept a push only if the client saw the latest version, else return the current blob); the client merges field by field and re-pushes. The "outbox" becomes a list of dirty records with their changed fields rather than an operation log. Same user-visible behaviour, far fewer failure modes. See §6.

**1.6 "Instantly available" will mean "within seconds while both apps are open and unlocked".**
Sync needs the vault key to merge, so it runs only while unlocked: on unlock, on change, on a timer (default 60 s in foreground), and on "Sync now". No Android background sync while the app is closed; you'd get the change when you open the app. Server push (SSE) is under Later.

**1.7 `xterm` (xterm.dart) is the right choice but is stale.**
Latest release is 4.0.0 from February 2024. It is still the de facto Flutter terminal (≈287k downloads/month). The active alternative, `kterm` 1.6.0 (October 2026, an xterm.dart fork), has one maintainer, 3 likes and ≈860 downloads/month, and pulls in image and Kitty-protocol dependencies we don't need. *Recommendation:* pin `xterm` 4.0.0 behind a thin wrapper of our own so swapping to `kterm` is a contained change. Clickable URLs, pinch zoom and the extra-keys row are not built in; we write them. First task of Phase 2 is a spike proving it builds and types correctly on current Flutter for both platforms. (I couldn't inspect either GitHub repo from this session, only the published packages.)

**1.8 Phase 2 "no encryption yet" — I'd rather never write a plaintext secret to disk.**
*Recommendation:* Phase 2 already stores secrets through the final AEAD envelope format, keyed by a random device key in OS secure storage. Phase 3 then only swaps where the key comes from (passphrase hierarchy). This also de-risks the libsodium build early.

**1.9 Move a foreground-service spike into Phase 2.**
Whether SSH sessions survive depends on where the Dart isolate holding the sockets lives when Android destroys the Activity. That's an architectural constraint, not polish. Spike in Phase 2; notification actions, Doze handling and kill detection stay in Phase 6.

**1.10 Drop Postgres from v1.**
One user, a few hundred small records. SQLite in WAL mode on a volume is simpler to deploy and back up (one file), and makes the monotonic sync cursor trivial. I'll use SQLAlchemy so Postgres stays possible later.

**1.11 Smaller points**
- **Dynamic SOCKS (`-D`) is in.** dartssh2 4.1.0 has `forwardDynamic` built in (SOCKS5, no-auth, CONNECT), so it costs little.
- **dartssh2 4.0 removed legacy algorithms from defaults** (`ssh-rsa` host keys, CBC ciphers, SHA-1 kex). Old switches/NAS boxes may fail to connect. I'll add a per-host "allow legacy algorithms" toggle, off by default.
- **dartssh2 has no key generation and no `.ppk` support.** Generation: ed25519 via libsodium, RSA-4096 via pointycastle (pure Dart; can take tens of seconds on a phone, so it runs in an isolate with a spinner). PPK v2/v3: we write the *file-format parser* using library primitives (AES-CBC, HMAC, Argon2 from pointycastle), tested against keys produced by `puttygen`. That's parsing, not a hand-rolled primitive.
- **Terminal encoding:** xterm.dart is UTF-8. v1 offers UTF-8 and Latin-1 only; others under Later.
- **Local DB metadata stays plaintext on the device** (hostnames, nicknames, usernames), same exposure as `~/.ssh/config` or PuTTY's registry. Only secrets are encrypted locally; everything is encrypted before leaving the device. The alternative (SQLCipher for the whole DB) adds a native dependency and blocks showing anything before unlock. See §11.
- **Last-connected time/status is per device, not synced.** Syncing it would create a write and potential conflict on every connect.
- **Imported encrypted keys are decrypted at import** and re-encrypted under the vault. One passphrase to remember, not one per key.
- **Self-signed / private-CA TLS:** Android apps don't trust user-installed CAs by default. v1 includes "pin this server certificate by SHA-256 fingerprint" in sync setup so a homelab CA works without plain HTTP.
- **Windows installer:** MSIX needs a certificate Windows trusts; a self-signed one must be installed on each PC first. Inno Setup `.exe` (unsigned, one SmartScreen click) is simpler for personal use. Recommend Inno.
- **Build reality:** Windows binaries need a Windows machine, so builds run on GitHub Actions (`windows-latest` + Ubuntu for Android). I can run Dart unit tests, server tests and the two-client integration test here; the manual device checklist is yours to run.
- **Host list from the Server Agent Hub (agreed):** Claude generates an `ssh_config`-format file from the hub's server list (nickname, IP, port, tags → groups); you import it in the app. No credentials, no new server endpoint. Re-import skips hosts already present (matched on hostname + port). The `ssh_config` importer therefore moves from Phase 6 to Phase 2, with a multi-select "assign credential" action in the host list.
- **I don't have the UI mockups.** Please add them under `docs/design/`; until then I'll follow the written structure and colours.

---

## 2. Architecture

```
┌──────────────────────── Flutter app (Android / Windows) ────────────────────────┐
│  UI (Riverpod)    Hosts · Sessions/Terminal · Vault · Sync · Settings           │
│  Adaptive shell   bottom nav (Android)  |  sidebar + tabs (Windows)             │
│  Platform glue    foreground service, FLAG_SECURE, clipboard flags, registry    │
├──────────────────────────────────────────────────────────────────────────────────┤
│  packages/core (pure Dart, no Flutter — fully unit-testable)                     │
│    SessionManager ── dartssh2 ──► SSH hosts                                      │
│    Repositories  ──► drift/SQLite   (source of truth for the UI)                 │
│    Vault         ──► libsodium      (key hierarchy, AEAD envelopes)              │
│    SyncEngine    ──► outbox, HLC, field merge, conflicts ──HTTPS──► sync server  │
│    Importers     ──► ssh_config, PuTTY registry, .ppk, OpenSSH keys              │
└──────────────────────────────────────────────────────────────────────────────────┘
                                             │ ciphertext only
                               ┌─────────────▼─────────────┐
                               │ FastAPI sync server       │  SQLite (WAL) on a volume
                               │ devices · tokens · blobs  │  behind your reverse proxy
                               └───────────────────────────┘
```

Rules that keep the three principles true:

- The UI reads and writes **only** the local DB. Nothing in the UI awaits the network.
- Every write goes through a repository that, in one SQLite transaction, updates the row, bumps the field clocks and marks the record dirty in the outbox.
- `SyncEngine` is a separate loop that can be absent entirely (no server configured) without any other component noticing.
- The vault key exists only in memory while unlocked. Lock = wipe key, hide UI behind the unlock screen. **Open SSH sessions keep running while locked**; reconnecting or opening a new one needs an unlock.
- Sessions are owned by `SessionManager`, not by widgets, so they survive navigation. On Android a foreground service keeps the process alive while any session is open.

---

## 3. Packages

Versions are the latest on pub.dev as of 2026-11-21. "Verified" means I read the published package source, not just the README.

| Purpose | Package | Version | Notes |
|---|---|---|---|
| SSH | `dartssh2` | 4.1.0 (2026-09) | Actively maintained. **Verified in source:** ed25519 / ECDSA P-256/384/521 / RSA (`rsa-sha2-256/512`) keys; encrypted OpenSSH keys (bcrypt-pbkdf + aes256-ctr), read and write; `onPasswordRequest`; `onUserInfoRequest` (keyboard-interactive); `keepAliveInterval`; `forwardLocal`, `forwardRemote`, `forwardDynamic`; `onVerifyHostKey(type, fingerprint)` giving the OpenSSH-style SHA256 fingerprint; host-key change on rekey aborts. Auth is tried publickey → password → keyboard-interactive, which is the spec's default order; "key only"/"password only" = supply only that method. `forwardLocal` returns a channel, so we bind the local listening socket ourselves. |
| Terminal | `xterm` | 4.0.0 (2024-02) | See 1.7. Wrapped behind our own interface. |
| Local DB | `drift` + `drift_flutter` + `sqlite3` | 2.35.4 / 0.3.1 / 3.9.1 | `sqlite3_flutter_libs` is end-of-life; sqlite3 3.x ships the native library itself. Works in plain Dart, so DB tests run without Flutter. |
| Crypto | `sodium` + `sodium_libs` | 4.1.5 / 4.0.1 | libsodium bindings. Verified present: `crypto_pwhash` (Argon2id), XChaCha20-Poly1305-IETF AEAD, secretstream, KDF, secure memory. v4 compiles libsodium at build time via Dart build hooks; needs Flutter ≥ 3.44. Chosen over `cryptography` (2.9.0, last release a year ago, Argon2id in pure Dart is slow on phones). |
| Key generation / PPK primitives | `pointycastle` | 4.0.0 | Already a dartssh2 dependency. RSA keygen, AES-CBC, HMAC, Argon2 (i/d/id) for PPK v3. |
| Secure storage | `flutter_secure_storage` | 11.2.0 | Android Keystore (biometric-enforced options verified to exist), Windows DPAPI. |
| Biometrics | `local_auth` | 3.0.2 | Android BiometricPrompt, Windows Hello. See 1.3. |
| State | `flutter_riverpod` | 3.5.0 | Plain Navigator for routing; no router package. |
| Android service | `flutter_foreground_task` | 11.0.3 | Foreground service + notification with action buttons. Service type `specialUse` (sideloaded, no Play review). |
| QR | `qr_flutter` / `mobile_scanner` | 4.1.0 / 7.5.0 | Show QR on both platforms; scan on Android only. |
| Windows | `win32_registry`, `window_manager` | 3.0.3 / 0.7.0 | PuTTY import; window title/size handling. `window_manager` needs Flutter ≥ 3.50. |
| Misc | `file_picker` 13.4.0, `path_provider` 2.1.6, `url_launcher`, `uuid`, `http` | | Remaining versions pinned in `pubspec.lock` at Phase 2 start. |
| Fonts | Inter, JetBrains Mono | bundled assets (OFL) | No runtime font downloads. |

Flutter: current stable at Phase 2 start, minimum 3.50. Android `minSdk` 26.

Server: Python 3.13, FastAPI, Uvicorn, SQLAlchemy 2, Pydantic 2, `slowapi` for rate limits, pytest + httpx. I have not version-checked these yet; they get pinned in a lockfile at Phase 4 start.

---

## 4. Data model

### 4.1 Synced records

Every synced record has a UUID `id`. All fields listed here are merged individually.

| Type | Fields |
|---|---|
| `group` | name, color, sort_order |
| `host` | nickname, hostname, port, credential_id, auth_order (`key_then_password` \| `key_only` \| `password_only`), group_id, tags[], color, pinned, notes, keepalive_seconds, startup_command, encoding, forwards[] (`{kind: L\|R\|D, bind_host, bind_port, dest_host, dest_port}`), allow_legacy_algorithms, auto_reconnect |
| `credential` | label, username, prompt_for_password, password*, private_key* (unencrypted OpenSSH PEM), public_key, key_type, key_fingerprint |
| `known_host` | host, port, key_type, fingerprint_sha256, trusted_at |
| `setting` | key, value (only settings flagged as synced, e.g. theme, default keepalive, scrollback) |
| `conflict` | record_id, record_type, field, winning_value, losing_value*, losing_device_id, both clocks, created_at |

\* secret: encrypted at rest locally (§5.3). `tags[]` and `forwards[]` each merge as one field.

IDs for `known_host` and `setting` are **deterministic but keyed**: `HMAC(K_id, "known_host|host|port|key_type")` truncated to 128 bits. Two devices that trust the same host offline produce the same record instead of duplicates, and the server cannot dictionary-guess hostnames from IDs.

### 4.2 Local SQLite tables (drift)

- One table per record type above with ordinary columns for non-secret fields (so search and sort are plain SQL) and a `secret_blob` column holding an AEAD envelope for secret fields.
- `sync_state(record_id PK, record_type, field_clocks JSON, synced_clocks JSON, deleted_clock, server_seq, dirty)`
  - `field_clocks`: current HLC per field. `synced_clocks`: clocks as of the last state exchanged with the server. A field is "changed locally since last sync" when the two differ. No plaintext values are stored here.
- `outbox(record_id PK, changed_fields JSON, first_changed_at, attempts, last_error)` — one row per dirty record, coalesced. This is what the Sync screen lists as pending.
- `vault_meta` — keyslot (salt, Argon2 parameters, wrapped vault key), key version, vault ID.
- `sync_config` — server URL, device ID, cursor, last success time, pinned certificate fingerprint, insecure-LAN flag. The device token and sync key live in OS secure storage, not here.
- `local_host_state(host_id, last_connected_at, last_status)` and local-only settings (auto-lock timeout, biometric toggle, sync interval, font zoom). **Never synced.**

Deletes set `deleted_clock` and clear the row's content (secrets included). Tombstones are kept indefinitely; at this scale that's kilobytes.

---

## 5. Crypto design

All primitives come from libsodium. Nothing custom below the level of "which bytes go into which library call".

### 5.1 Key hierarchy (key-encryption-key design)

```
master passphrase ──Argon2id(salt, params)──► KEK ──┐
                                                    ├─ XChaCha20-Poly1305 ─► wrapped VK   = "keyslot"
random 32-byte Vault Key (VK), made once ───────────┘

VK ──libsodium KDF──► K_local   encrypts secret_blob columns in the local DB
                 ├──► K_sync    encrypts record payloads sent to the server
                 ├──► K_id      HMAC key for deterministic record IDs
                 └──► K_backup  not used directly; backups carry their own keyslot
```

- **Changing the master passphrase** makes a new salt and KEK and re-wraps the same VK. No record is re-encrypted, and the change is one small atomic write. That's the point of the KEK design.
- **Biometric unlock** stores a second copy of VK in the OS keystore (Android: Keystore key requiring strong biometric; Windows: DPAPI, gated by a Hello prompt — see 1.3). Disabling biometrics deletes that copy. Changing the passphrase doesn't affect it.
- **Lock** zeroes VK and derived keys (libsodium secure memory) and drops decrypted secrets from app state.

### 5.2 Argon2id parameters

Argon2id v1.3, **memory 64 MiB, 3 passes, parallelism 1** (libsodium is single-lane), 16-byte random salt, 32-byte output. This is above OWASP's minimum (19 MiB / 2 passes) and safe on a 3–4 GB phone; expected unlock time is roughly 0.3–1 s on mid-range Android, which I'll measure on your device in Phase 3 and adjust. Parameters are stored in the keyslot, so they can be raised later with a re-wrap. Passphrase entry enforces a minimum length of 12 and shows a strength estimate.

### 5.3 Record encryption

- Algorithm: XChaCha20-Poly1305-IETF, fresh random 24-byte nonce per encryption.
- Envelope: `version(1) ‖ key_version(1) ‖ nonce(24) ‖ ciphertext+tag`.
- **Synced payload:** the *entire* record — type, all field values, all field clocks — serialised to JSON, padded to a multiple of 256 bytes (libsodium padding), encrypted with `K_sync`. Associated data = `"sshsync/v1" ‖ vault_id ‖ record_id ‖ key_version`, so the server cannot move a blob to another record ID undetected.
- **What the server can still see:** record IDs (random or keyed), blob sizes rounded to 256 bytes, when each changed, which device pushed it, and whether it's a tombstone. It cannot see record types, hostnames, usernames, tags or anything else. No case for server-side search; none is made.
- **Local secret_blob:** same envelope with `K_local`, associated data = record ID + column name.
- **What a malicious server could still do:** withhold changes or replay an old blob. A replayed blob merges as a no-op because its field clocks are older; tombstones can't be undone the same way. It cannot read or forge anything.

### 5.4 Sync key and enrollment (pending decision 11.1)

- First device with sync enabled generates `SK`, 32 random bytes, kept in OS secure storage.
- Uploaded to the server: `seal(SK, keyslot)` — the passphrase-wrapped VK, encrypted again under SK. The server can neither brute-force it nor substitute a fake one.
- New device: QR carries `{server URL, one-time code, SK, optional cert fingerprint}`. Device enrolls, downloads the sealed keyslot, opens it with SK, asks for the master passphrase, unwraps VK, pulls everything.
- Passphrase change on device A uploads a new sealed keyslot; device B picks it up on next sync (it holds SK), after which only the new passphrase works on B.
- The Vault screen can show SK again (after passphrase re-entry) for a printed recovery sheet.

### 5.5 Encrypted backup file

Self-contained: magic + version, its own Argon2 salt/parameters and wrapped random file key, then a libsodium secretstream of the full record dump. Protected by the master passphrase alone (no server, no SK needed), so it restores onto a clean install. Export warns that the file is exactly as strong as the passphrase.

### 5.6 Secret hygiene

- No secret is ever passed to a logger; log calls take typed, redacting wrappers. dartssh2's `printTrace` stays off (it logs packet contents).
- Clipboard: copying a secret marks it sensitive on Android 13+ and excluded from Windows clipboard history/cloud sync, and clears it after 30 s if unchanged. Public keys copy normally.
- Android: `FLAG_SECURE` on unlock, vault, credential and enrollment-QR screens; a setting extends it to the whole app.
- No crash reporting, analytics or network calls other than SSH and your sync server.

---

## 6. Sync protocol

### 6.1 Clocks

Hybrid Logical Clock per field: `(wall_ms, counter, device_id)`, compared in that order. A device's clock never goes backwards and always moves past any clock it has seen. Incoming clocks more than 24 h ahead of local time are flagged in the Sync screen rather than silently winning forever.

### 6.2 Server contract

The server keeps, per record: `id, seq, deleted, blob, device_id, updated_at`. `seq` is one global counter that increases on every accepted write; it's the pull cursor.

- **Push** `{id, base_seq, deleted, blob}` — accepted only if `base_seq` equals the record's current `seq` (0 for new). Otherwise the item is rejected with the current `{seq, blob}`.
- **Pull** `since=<cursor>` — returns changed records in `seq` order, paged, with the next cursor.

### 6.3 Client cycle

1. **Pull** from the stored cursor. For each record: decrypt, merge into local (below), store `server_seq`.
2. **Push** every outbox record as the full current record, with its `server_seq` as `base_seq`.
3. On rejection: merge the returned blob, re-push. Bounded retries, then leave in the outbox with the error shown.
4. Advance the cursor and clear outbox rows only after the local transaction commits.

Crash safety: if the server accepted a push but the reply was lost, the retry is rejected with a blob identical to ours, the merge is a no-op, and we record the `seq`. Replaying the outbox is always safe.

### 6.4 Field merge and conflicts

For each field, with local value/clock `L`, remote `R`, and `S` = clock at last sync:

| Situation | Result |
|---|---|
| clocks equal | nothing to do |
| local unchanged since sync (`L.clock == S`) | take remote |
| remote unchanged (`R.clock == S`) | keep local |
| both changed, same value | keep value, take the later clock |
| both changed, different values | **later clock wins; write a `conflict` record** holding the losing value, its device and both clocks |

- **Delete vs. edit:** delete wins, and a conflict record keeps the edited version with a "Restore" action.
- Conflict records are themselves synced, so you can resolve on either device. Resolving = "keep current" (delete the conflict) or "use other value" (a normal field write, then delete the conflict). Nothing is ever dropped without a conflict record.
- A deleted credential still referenced by a host leaves the host with "no credential" and a visible warning rather than failing.

### 6.5 Triggers and offline behaviour

On unlock, 2 s after any local change (debounced), every N seconds in foreground (default 60, configurable), and "Sync now". Failures back off exponentially up to 5 minutes and flip the Sync screen to Offline; nothing else in the app changes. With no server configured the outbox isn't populated at all; enabling sync later marks every record dirty once.

### 6.6 Transport rules

- HTTPS required. Plain HTTP is accepted only when the host is loopback, RFC 1918, link-local, or a `.local`/`.lan`/`.home.arpa` name **and** you tick "allow insecure LAN sync" for that server; a permanent warning then shows on the Sync screen. (Payloads are still end-to-end encrypted; the exposure is the device token.)
- Optional certificate pin by SHA-256 fingerprint for self-signed/private-CA servers.

---

## 7. Sync server

Single vault, single user. FastAPI + SQLite (WAL) in one container, one volume.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | liveness, no data |
| `POST /v1/enroll` | one-time code | `{code, device_name, platform}` → `{device_id, token, vault_id}` |
| `POST /v1/enrollment-codes` | device | create a 10-minute single-use code |
| `GET/PUT /v1/keyslot` | device | sealed keyslot blob, versioned |
| `POST /v1/push` | device | batch of changes, per-item accepted/rejected |
| `GET /v1/pull?since=&limit=` | device | changes after cursor |
| `GET /v1/devices` | device | name, platform, enrolled, last seen, revoked |
| `DELETE /v1/devices/{id}` | device | revoke (a device may revoke itself or any other) |
| `POST /v1/devices/self/rotate-token` | device | new token, old one dies |
| `GET /v1/status` | device | server time, record count, protocol version |

- **Bootstrap:** on first start with an empty database the server prints a one-time enrollment code to its log; `docker compose exec server sshsync enroll-code` makes another if all devices are lost. No admin account, no web UI.
- **Tokens:** 256 random bits, sent as `Authorization: Bearer`. Only a SHA-256 hash is stored. Shown to the device once.
- **Enrollment codes:** 10 characters from an unambiguous alphabet (~50 bits), stored hashed, single use, 10-minute expiry.
- **Rate limits:** enrollment 5/min per IP with lockout after repeated failures; failed auth 10/min per IP; push/pull generous. Honours `X-Forwarded-For` only from a configured trusted proxy.
- **Validation:** Pydantic models on everything; UUID IDs; blob ≤ 256 KiB; batch ≤ 500; request body ≤ 8 MiB. Uniform JSON errors `{error: {code, message}}`; a global handler turns unexpected exceptions into a 500 with a request ID.
- **Logging:** method, path, status, device ID, request ID, sizes. Never bodies, tokens, codes or blobs.
- **Deliverables:** `Dockerfile` (non-root, slim), `docker-compose.yml`, README covering VM deployment, Caddy/nginx/Traefik TLS examples, volume backup and restore (`sqlite3 .backup`), token rotation, upgrade.

---

## 8. Repo layout

```
app/                    Flutter application
  android/  windows/
  lib/
    main.dart  app_shell/ (adaptive nav)  theme/
    features/ hosts/ terminal/ vault/ sync/ settings/ import/
    platform/ (foreground service, FLAG_SECURE, clipboard, registry)
  assets/fonts/
  test/                 widget tests
packages/core/          pure Dart; no Flutter imports
  lib/src/
    db/        drift schema, repositories
    vault/     key hierarchy, envelopes, backup format
    ssh/       SessionManager, auth order, known hosts, forwards, install-key
    sync/      hlc, merge, outbox, engine, api client
    import/    ssh_config, ppk, openssh keys, putty sessions (parser only)
  test/
server/
  app/  tests/  Dockerfile  docker-compose.yml  README.md
integration/            compose file + Dart two-client tests against a real server
docs/                   PLAN.md, design/ (mockups), MANUAL_TESTS.md, later CRYPTO.md / SYNC_PROTOCOL.md split out of this file
.github/workflows/      core tests, server tests, integration, Android + Windows builds
README.md
```

Putting the logic in `packages/core` is what makes the acceptance tests cheap: the integration test's "two simulated clients" are two instances of the real sync engine with in-memory databases, not a reimplementation.

---

## 9. Phases

Each phase ends with: tests run, summary of built / remaining / deviations, stop for review.

| # | Phase | Scope | Changes from your spec |
|---|---|---|---|
| 1 | Plan | this document | — |
| 2 | Local client core | Repo scaffold + CI. Flutter project (Android + Windows). drift schema incl. sync_state columns. Hosts/groups CRUD, search, sort, duplicate. Quick connect + "save this host". Terminal with tabs, resize, scrollback, copy/paste, extra-keys row with sticky Ctrl/Alt. Password, key and keyboard-interactive auth with the three auth orders. Known-hosts TOFU + changed-key block screen. Keepalive, startup command. `ssh_config` import (file picker) + bulk assign credential. | **Added:** secrets go through the real AEAD envelope with a device-random key (1.8); xterm and foreground-service spikes (1.7, 1.9); legacy-algorithms toggle. |
| 3 | Vault | Master passphrase, Argon2id keyslot, key hierarchy, migrate Phase-2 device key → VK. Unlock screen, auto-lock, manual lock, change passphrase. Biometric unlock. Generate ed25519/RSA-4096; import OpenSSH (encrypted or not) and `.ppk`; export/copy public key. Install key on server + offer "key only". Prompt-on-connect credentials. FLAG_SECURE. Clipboard handling. Loss-of-passphrase warning. | Encrypted backup export/import moved **here** from Phase 6: the "you can't recover this" warning should ship with its remedy. |
| 4 | Sync server | Everything in §7, tests, Docker image, compose, README. | SQLite only (1.10). |
| 5 | Client sync | HLC, outbox, engine, merge, conflict records and UI, Sync screen, enrollment (QR + manual), sync key, device list/revoke, token rotation, HTTP/LAN rule, cert pinning, keyslot propagation on passphrase change. Two-client integration test. | Sync key (1.1), cert pin. |
| 6 | Polish | Foreground service notification + disconnect action, Doze/battery-exemption prompt, killed-session notice. Auto-reconnect with backoff. Port forwards L/R/D with in-session status. PuTTY registry import. Windows shortcuts and two-pane split. Themes, fonts, pinch/Ctrl+wheel zoom, clickable URLs, volume-key zoom. Light theme. Accessibility pass. | `-D` included. |
| 7 | Packaging | Signed release APK, Windows installer, tagged server image, top-level README, manual test checklist run. | Inno Setup recommended over MSIX. |

Phase 2 is the largest. If you'd like smaller review units I'd split it into 2a (scaffold, DB, hosts UI) and 2b (SSH, terminal, known hosts).

---

## 10. Testing

**Unit (`packages/core`, run on every commit)**
- Crypto: round-trip; wrong passphrase fails; any flipped byte in nonce, ciphertext, tag or associated data fails; blob moved to another record ID fails; passphrase change keeps data readable; backup round-trip; published Argon2id and XChaCha20-Poly1305 test vectors.
- Merge: every row of the §6.4 table; delete vs. edit; clock ties; clock skew; list-valued fields; merge is commutative and idempotent (property test with random edit sequences on two or three replicas converging).
- Outbox: coalescing; replay after simulated crash at each step; lost-reply retry; tombstone propagation; enabling sync late.
- SSH: auth-order selection; known-hosts decisions; `user@host:port` parsing incl. IPv6; ssh_config parser; PPK v2/v3 and OpenSSH keys against `puttygen`/`ssh-keygen` output. Connection tests run against an OpenSSH server container.

**Server (pytest):** enrollment (valid, reused, expired, rate-limited), auth and revocation, push/pull ordering and paging, conflict rejection, oversized and malformed input, log output contains no payloads or tokens.

**Integration (real server in Docker, two real sync engines):**
(a) host added on A appears on B · (b) both edit offline, reconnect: different fields merge, same field yields a conflict record visible on both · (c) delete on A removes on B · (d) the server's SQLite file and its WAL are scanned for every hostname, username, password and key fragment used in the test, and none may appear · plus: revoked device is refused; server stopped mid-test leaves both clients fully usable.

**Manual checklist (`docs/MANUAL_TESTS.md`, per platform):** password / key / key→password fallback; keyboard-interactive; changed-fingerprint block; install-key; session survives backgrounding and screen-off on Android; biometric unlock; auto-lock; every screen usable with the server stopped; enrollment by QR and by hand; revoke.

---

## 11. Decisions I need from you

1. **Sync key (1.1)** — adopt it? *Recommended: yes.* Without it, server compromise reduces to "how strong is your passphrase".
2. **Postgres (1.10)** — drop from v1? *Recommended: yes.*
3. **Local metadata** — plaintext hostnames/usernames in the on-device DB, secrets encrypted? *Recommended: yes.* Alternative is whole-DB encryption with SQLCipher.
4. **Terminal package (1.7)** — pinned `xterm` 4.0.0 behind a wrapper, with `kterm` as fallback? *Recommended: yes.*
5. **Phase changes (§9)** — real encryption envelope and service spike in Phase 2; backup in Phase 3. OK?
6. **Windows installer** — Inno Setup `.exe`? *Recommended: yes.*
7. **CI** — GitHub Actions on this repo for tests and Windows/Android builds? Release signing keys would be repository secrets that you create.
8. **Mockups** — can you add them to `docs/design/`?

## Later (unchanged, plus items moved out above)

SFTP, Mosh, serial/telnet, iOS/macOS/Linux, snippets, team sharing, AI features, health dashboards · vault-key rotation after revocation · server-push sync (SSE) · Android background sync while closed · encodings beyond UTF-8/Latin-1 · Postgres · jump hosts / agent forwarding (dartssh2 supports both; cheap to add if wanted).
