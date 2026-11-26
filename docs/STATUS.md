# Status

Last updated 2026-11-21. Phases 2–6 of `PLAN.md` were built in one pass, plus
most of Phase 7 (packaging). Nothing here has been run on a physical Android
phone or a physical Windows PC yet; that is what `MANUAL_TESTS.md` is for.

## What was verified, and how

| Area | How it was checked | Result |
|---|---|---|
| Sync server | 51 pytest tests; run live with uvicorn; Docker image built and exercised in CI | passes |
| Vault, encryption, backup | Unit tests on real libsodium: round trip, wrong passphrase, every byte tampered, blob moved to another record, passphrase change | passes |
| Merge and clocks | Unit tests for every merge case, plus 200 random three-replica runs that must converge | passes |
| Sync engine | Two engines against an in-memory server: add, offline edits, conflict, delete, lost reply, paging, revoke, keyslot | passes |
| Acceptance (a)–(d) | Two real engines against the real server (uvicorn locally, Docker in CI); server database and WAL scanned for plaintext | passes |
| SSH | Real OpenSSH server: password, key, key→password, wrong password retry, trust on first use, changed host key, install key, jump host, local/remote/SOCKS forwards | passes locally and in CI |
| Key import | Against `ssh-keygen` and `puttygen` output: OpenSSH, legacy PEM, PuTTY v2 and v3, five key types, encrypted and not | passes |
| App UI | Built for Linux and driven in a virtual display: create vault, wrong/right unlock, quick connect, host-key prompt, password prompt, live terminal, save host, generate key, connect to sync server (HTTP refused until allowed), add-device QR, settings, phone-width layout | works |
| Android APK, Windows build + installer | GitHub Actions | see the latest run |

Total: 110 core tests, 51 server tests, 2 app tests.

## Not verified (needs your devices)

- Anything Android-specific at run time: the foreground service and its
  notification, biometric unlock through the Keystore, FLAG_SECURE, the
  sensitive-clipboard flag, QR scanning, the on-screen keyboard and extra-keys
  row, Doze behaviour.
- Anything Windows-specific at run time: idle and Win+L auto-lock, the
  built-in updater, DPAPI storage, PuTTY
  registry import, the installer.
- Whether sessions survive swiping the app out of recents on Android. The
  service keeps the process alive, but Android may still destroy the Flutter
  engine with the Activity. If it does, the fix is a cached engine owned by
  the Application; the app tells you on next start if sessions were cut off.
- Argon2id unlock time on your phone (expected well under a second).

## Deviations from the plan

1. **No `drift`.** The local database is one generic `records` table accessed
   through the `sqlite3` package directly. With every record type merged
   field by field in the same way, typed tables and code generation added
   moving parts without adding safety. Search and sort happen in memory,
   which is fine for hundreds of hosts.
2. **No Riverpod.** One `ChangeNotifier` (`App`) plus `ListenableBuilder`.
3. **No interim "device key" stage.** The vault and passphrase exist from the
   first run, so there was never a build that stored secrets differently.
4. **Outbox is a `dirty` flag per record**, with changed fields derived from
   clocks, rather than a separate table. Same behaviour, one less thing to
   keep consistent.
5. **A revoked device does not erase itself.** It stops syncing and tells
   you. Auto-erase on a server's say-so would let a server bug or a restored
   backup wipe your devices. "Erase this device" is in Settings.
6. **Password retry reconnects.** The SSH library offers a password once per
   connection, so after a refusal the app asks again and reconnects (up to
   twice).
7. **Desktop typing bypasses the terminal widget's text-input path**, which
   duplicated characters under fast typing. Keys are read directly instead.
   Side effect: no dead-key/IME composition in the desktop terminal yet.
8. **`package:flutter/material.dart` is used although Flutter 3.50 deprecates
   it** in favour of `material_ui`: `xterm` 4.0.0 still depends on the old
   library and the two do not mix.
9. **Linux desktop also builds.** It was needed to see the UI during
   development; it is not a supported target.

## Not built

- **Sync through the jump host.** Jump hosts for SSH sessions work. Routing
  the sync HTTP traffic through one is not built; use TLS, WireGuard, or a
  LAN address for the sync server for now.
- **Windows clipboard-history exclusion.** Copied secrets are cleared after
  30 seconds on both platforms and flagged sensitive on Android; they can
  still land in Windows clipboard history (Win+V) if you have it turned on.
- **Detecting a server restored from an older backup.** A device whose cursor
  is ahead of the restored server would miss changes until you disconnect and
  reconnect it.
- **Secure memory for keys.** Keys are zeroed on lock but held in ordinary
  Dart memory while unlocked, not in libsodium's guarded allocations.
- **Automated UI tests** beyond two smoke tests.
- **UI mockups were never available to me**, so the screens follow the
  written description (structure, colours, fonts), not the drawings.

## Known rough edges

- `xterm` 4.0.0 is unmaintained upstream (see PLAN 1.7). It works on Flutter
  3.50 today. The terminal is isolated in `app/lib/ui/terminal.dart` if it
  needs replacing.
- RSA-4096 generation is pure Dart and slow on phones (tens of seconds).
- Android release builds are signed with a debug key until you add your own
  (README).
- The first Linux run asks for a keyring password; that is the desktop
  keyring, not this app, and does not apply to Android or Windows.
