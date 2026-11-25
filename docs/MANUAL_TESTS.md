# Manual test checklist

Run on a real Android phone and a real Windows PC. Automated tests cover the
logic; this covers what only a device can show. Tick each box per platform.

## Setup
- [ ] Install. Create a vault. A passphrase under 12 characters is refused; mismatched repeats are refused.
- [ ] Close and reopen: the unlock screen appears; a wrong passphrase is refused; the right one opens.

## Connecting
- [ ] Quick connect `user@host`: host-key prompt shows a fingerprint that matches `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server.
- [ ] "Save this host" after quick connect creates the host and a prompt-for-password credential.
- [ ] Password login with a stored password.
- [ ] Key login: generate an Ed25519 key, "Install on server", accept "Key only", reconnect without a password prompt.
- [ ] Key → password fallback: credential with a key the server does not know plus the right password connects.
- [ ] Wrong stored password: you are asked again; Cancel ends cleanly.
- [ ] Server with keyboard-interactive / 2FA prompts for each answer.
- [ ] Change the server's host key (or point the host at another machine): the red "Host key has changed" dialog appears, shows old and new, and defaults to not connecting.
- [ ] Host with a jump host connects through it; both hops ask to trust their keys the first time.

## Terminal
- [ ] `htop`, `vim`, `tmux` draw correctly; resize/rotate reflows.
- [ ] Colours: `ls --color`, a 256-colour and a truecolour test script.
- [ ] Select text, copy, paste. Windows: Ctrl+Shift+C / Ctrl+Shift+V.
- [ ] Tap a URL in output: "Open" appears and opens the browser.
- [ ] Font zoom: pinch (Android), Ctrl+wheel and Ctrl+plus/minus (Windows).
- [ ] Two sessions as tabs; switch screens and come back: scrollback intact.
- [ ] Android: extra-keys row. Ctrl then `c` interrupts; Esc, Tab, arrows, Home/End, PgUp/PgDn work; Ctrl/Alt highlight while armed.
- [ ] Android: hardware keyboard types correctly, including Ctrl combinations.
- [ ] Windows: Ctrl+Tab / Ctrl+Shift+Tab switch tabs, Ctrl+Shift+W closes, Ctrl+Shift+T focuses quick connect, split view shows two sessions.
- [ ] Windows: type quickly and with AltGr characters (`@`, `{`, `|` on non-US layouts): no doubled or missing characters.

## Background and reconnect (Android)
- [ ] With a session open, a notification "1 SSH session active" appears; "Disconnect all" works.
- [ ] Press Home, wait 10 minutes with the screen off, return: the session is still alive (`date` responds).
- [ ] Swipe the app away from recents: note whether the session survives (see STATUS.md).
- [ ] Turn off Wi-Fi: the session shows a disconnected banner with Reconnect. With "Reconnect automatically" on, it retries with growing delays.

## Port forwarding
- [ ] Local forward: browser on the device reaches a web UI on the server's LAN.
- [ ] Remote forward and SOCKS forward show as active in the session bar; a taken port shows an error instead.

## Vault
- [ ] Import an OpenSSH key (encrypted and not) and a PuTTY `.ppk`; copy/export the public key.
- [ ] Auto-lock: set 1 minute, background the app for 2 minutes: locked on return, sessions still running.
- [ ] Biometric unlock on Android (fingerprint) and Windows (Hello).
- [ ] Android fingerprint, every unlock: turn it on (it asks once), lock, unlock: asked. Background past auto-lock and come back five times: asked every time, never unlocked silently. Repeat with an SSH session open (the foreground service keeps the app alive).
- [ ] Android: force-stop the app, open it: asked again.
- [ ] Android: add a fingerprint in the phone's Settings, open the app: it says fingerprint unlock was reset, the passphrase works, the switch is off in Settings, and sync still works (its token was not touched).
- [ ] Android 12+: Settings > System > Backup (or a new-phone transfer) carries no SSH Sync data.
- [ ] Android: try a plain `http://` LAN sync server with the insecure switch on. Note whether Android blocks it.
- [ ] Android: screenshots of the vault, credential and add-device screens are blocked and the app is blank in recents while locked.
- [ ] Change the master passphrase; old one refused, new one works.
- [ ] Export a backup, erase the device, create a new vault, import the backup: everything returns.

## Sync
- [ ] Telegram code: on device A enter only the server address, tap "Send code to Telegram"; the code arrives in Telegram naming the device; type it and Connect. A second tap within a minute still works; a fourth is refused as too many.
- [ ] Connect device A to the server. Add device B by QR and once more by typing the three values.
- [ ] Host added on A appears on B within about a minute, or at once with "Sync now".
- [ ] Host key trusted on A is not asked again on B.
- [ ] Both offline: change the nickname on both and a different field on each. Back online: other fields merge, the nickname shows a conflict card on both; "Use the other value" works.
- [ ] Delete on A removes on B.
- [ ] Stop the server: every screen still works, the Sync screen says Offline and lists pending changes; start it again and they upload.
- [ ] `http://` to a public address is refused; `http://` to a LAN address needs the explicit switch and shows a permanent warning.
- [ ] Revoke B from A: B shows "revoked", keeps its data, and stops syncing.
- [ ] Change the passphrase on A; after B syncs, B unlocks with the new one only.

## Import (Windows)
- [ ] "Import from PuTTY" brings in saved sessions and their `.ppk` keys.
- [ ] "Import ssh_config file" with your `~/.ssh/config`; importing twice adds nothing new.
