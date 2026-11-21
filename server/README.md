# sshsync server

The sync server for the synced SSH client. One vault, one user, a handful of
devices. It is **untrusted storage**: it keeps opaque encrypted blobs and hands
them back. It has no admin account and no web UI.

- Python 3.13, FastAPI, SQLite in WAL mode. One container, one volume.
- Everything it stores is in one file: `/data/sshsync.db`.

## What the server can and cannot see

It **can** see: record IDs (random UUIDs), the size of each encrypted blob,
when a record changed, which device pushed it, whether it is a tombstone,
device names and platforms, and client IP addresses.

It **cannot** see: hostnames, usernames, passwords, private keys, tags, record
types, or anything else inside a record. Records are encrypted on the device
before upload. The keyslot it stores is sealed under a sync key that never
reaches the server, so stealing the database gives nothing to brute-force.

A hostile or broken server could still withhold changes, serve old ones, or
delete everything. It cannot read or forge records. Keep your own backups.

Device tokens and enrollment codes are stored only as SHA-256 hashes, and are
never written to the log. The single exception is the enrollment code the
server prints for you on first start (and when you ask for one on the CLI).

## Quick start on a Linux VM

Needs Docker with the compose plugin.

```sh
git clone <this repo> && cd synced-ssh-client/server
docker compose up -d --build
docker compose logs server      # shows the first enrollment code
```

The log shows something like:

```
============================================================
 No device is enrolled yet.
 Enrollment code: ABCDE-FGHJK
 Single use, valid for 10 min 0 s.
============================================================
```

Type that code into the app on your first device (dashes, spaces and case do
not matter). If it expired before you used it, make a new one:

```sh
docker compose exec server sshsync enroll-code
```

Later devices are added from an already enrolled device (the app creates the
code and shows it as a QR code).

By default the port is published on `127.0.0.1:8080` only. The server speaks
plain HTTP, so do one of the following before pointing a device at it:

1. put a TLS reverse proxy in front of it (next section), or
2. reach it only through an SSH jump host or WireGuard (section after that).

Check it is up: `curl http://127.0.0.1:8080/healthz` returns `{"status":"ok"}`.

### Without Docker

```sh
uv sync --no-dev
SSHSYNC_DB_PATH=./data/sshsync.db uv run uvicorn app.main:create_app --factory \
    --host 127.0.0.1 --port 8080 --workers 1 --no-proxy-headers --no-access-log
```

Always run exactly one worker: rate limits are counted in process memory.

## Reverse proxy with TLS

The proxy terminates TLS and forwards to `127.0.0.1:8080`. Request bodies can
be up to 8 MiB.

So that rate limits count per real client instead of per proxy, tell the
server which address the proxy connects from, in `docker-compose.yml`:

```yaml
SSHSYNC_TRUSTED_PROXIES: "172.16.0.0/12"
```

With the proxy on the Docker host, the container sees it as the Docker bridge
gateway, which is inside `172.16.0.0/12` on a default install. Check with
`docker network inspect server_default | grep Gateway` and narrow it to that
one address if you like. `X-Forwarded-For` from any other address is ignored.
If you leave the setting empty everything still works; all clients then share
one rate-limit bucket (the proxy's address).

### Caddy

```
sync.example.com {
    reverse_proxy 127.0.0.1:8080
    request_body {
        max_size 9MB
    }
}
```

Caddy gets and renews the certificate itself and sets `X-Forwarded-For`.

### nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name sync.example.com;

    ssl_certificate     /etc/letsencrypt/live/sync.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sync.example.com/privkey.pem;

    client_max_body_size 9m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

`X-Forwarded-For $remote_addr` (not `$proxy_add_x_forwarded_for`) makes nginx
overwrite whatever the client sent.

With a private CA or a self-signed certificate, pin the certificate's SHA-256
fingerprint in the app's sync setup.

## Not exposing it publicly: SSH jump host or WireGuard

You do not need a public reverse proxy at all.

**SSH jump host.** Leave the port on `127.0.0.1:8080` (or on the VM's LAN
address). In the app, set the sync server to be reached through your saved
jump host; the app opens the tunnel itself and treats it as a safe transport
for plain HTTP. From a laptop the equivalent by hand is:

```sh
ssh -N -L 8080:127.0.0.1:8080 -p <port> you@jump.example.net
# then use http://127.0.0.1:8080
```

(Use the sync VM's LAN address instead of `127.0.0.1` in `-L` if the jump host
is a different machine, and publish the port on that address in
`docker-compose.yml`.) The jump host should be a small dedicated VM: key-only
login, no root login, nothing else on it.

**WireGuard.** Run WireGuard on the VM or your router, publish the port on the
VM's WireGuard address only (for example `"10.8.0.1:8080:8080"`), and use
`http://10.8.0.1:8080` in the app with "allow insecure LAN sync" ticked.
With the VPN up the app needs nothing special. Payloads are end-to-end
encrypted either way; what the tunnel protects is the device token.

## Backups and restore

Everything is in the `sshsync-data` volume. The database runs in WAL mode, so
recent writes live in `sshsync.db-wal` next to the main file. **Do not copy
`sshsync.db` on its own while the server runs**: you can get a stale or
inconsistent copy. Use SQLite's online backup, which is safe while running:

```sh
# make a consistent snapshot inside the volume, then copy it out
docker compose exec server python -c "
import sqlite3
src = sqlite3.connect('/data/sshsync.db')
dst = sqlite3.connect('/data/backup.db')
src.backup(dst); dst.close(); src.close()"
docker compose cp server:/data/backup.db ./sshsync-$(date +%F).db
```

That is the same operation as `sqlite3 /data/sshsync.db ".backup /data/backup.db"`;
the image ships Python but not the `sqlite3` command-line tool. If you have
`sqlite3` on the host and the volume mounted there, the CLI form works too.

Alternatively stop the server and copy the files; when it has stopped cleanly
the WAL is folded back into the main file:

```sh
docker compose stop server
docker run --rm -v server_sshsync-data:/data -v "$PWD":/out busybox \
    sh -c 'cp /data/sshsync.db* /out/'
docker compose start server
```

(The volume is named `<compose project>_sshsync-data`; `docker volume ls` shows it.)

**Restore:**

```sh
docker compose stop server
docker run --rm -v server_sshsync-data:/data -v "$PWD":/in busybox sh -c \
    'rm -f /data/sshsync.db-wal /data/sshsync.db-shm &&
     cp /in/sshsync-2026-01-01.db /data/sshsync.db && chown 10001:10001 /data/sshsync.db'
docker compose start server
```

Remove the old `-wal` and `-shm` files as shown: a leftover WAL must not be
applied to a different database file.

After restoring an *older* backup, devices that synced after it was taken hold
a newer cursor than the server, and the server will hand out sequence numbers
those devices think they have already seen. Each device then has to start
syncing again from cursor 0 and re-upload its records (a device can notice
this: `GET /v1/status` reports a `cursor` lower than its own). Do not carry on
as if nothing happened.

The backup holds only ciphertext, device names and token hashes. It is still
worth keeping private. The app's own encrypted export is the backup that
restores onto a clean install without any server.

## Tokens, revoking devices, recovery

- **Rotate a token:** done from the app on the device itself
  (`POST /v1/devices/self/rotate-token`). The old token stops working at once. Do this if a token may have leaked (for example
  after using plain HTTP on a network you do not trust).
- **Revoke a device:** from the device list in the app on any enrolled device
  (`DELETE /v1/devices/{id}`). The token dies immediately and the device gets `401 device_revoked`. Revoking
  stops future sync only. That device still has every secret it had already
  synced, so change the passwords and keys it knew.
- **Lost every device (or revoked them all):** the data is still on the
  server. Create a new code on the VM and enroll a new device with it:

  ```sh
  docker compose exec server sshsync enroll-code
  ```

  Restarting the server while no active device exists also prints a new code.
  You will still need your master passphrase and your sync key (recovery
  sheet) to decrypt anything. Without them the data cannot be recovered by
  anyone, including you. Then revoke the lost devices from the new one.
- Anyone who can run commands on the VM can enroll a device. That gives them
  ciphertext only, but protect the VM accordingly.

## Upgrading

```sh
# take a backup first (see above)
git pull
docker compose up -d --build
docker compose logs --tail 20 server
```

The database file is kept; the volume is not touched by a rebuild. To go back,
check out the previous version and rebuild, restoring the backup if the newer
version changed the schema (release notes will say so).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SSHSYNC_DB_PATH` | `/data/sshsync.db` | SQLite database file. Its directory must be writable (WAL files are created beside it). |
| `SSHSYNC_TRUSTED_PROXIES` | empty | Comma-separated IPs/CIDRs of reverse proxies. `X-Forwarded-For` is used for rate-limit keying only when the connection comes from one of them. |
| `SSHSYNC_RATE_LIMIT` | `on` | `on` or `off`. Leave on outside of tests. |
| `SSHSYNC_CODE_TTL_SECONDS` | `600` | Lifetime of an enrollment code. |
| `SSHSYNC_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. `WARNING` hides the per-request lines. |

Rate limits (per minute): 5 enrollment attempts per IP, 10 failed
authentications per IP, 600 authenticated requests per device. Over the limit
the answer is `429` with `Retry-After: 60`.

Fixed limits: request body 8 MiB, 500 changes per push, 256 KiB per record
blob, 16 KiB for the keyslot, 500 changes per pull page.

## Logs

One line per request: method, path, status, device ID, request ID, bytes in
and out, duration. No bodies, query strings, headers, tokens, codes or blobs.
Every response carries `X-Request-Id`; quote it to find the matching line.

```
2026-11-21 14:44:01,502 INFO POST /v1/push 200 device=79a0… request_id=3eb3… in=106 out=92 ms=9
```

## API summary

All JSON. Blobs are standard base64. Errors are
`{"error": {"code": "...", "message": "..."}}`. Every response has
`X-Request-Id` and `X-Server-Time` (unix ms).

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | liveness |
| `POST /v1/enroll` | one-time code | enroll a device, returns its token once |
| `POST /v1/enrollment-codes` | device | create a single-use code |
| `GET` / `PUT /v1/keyslot` | device | sealed keyslot, versioned |
| `POST /v1/push` | device | batch of changes, accepted or rejected per item |
| `GET /v1/pull?since=&limit=` | device | changes after a cursor |
| `GET /v1/devices` | device | list devices |
| `DELETE /v1/devices/{id}` | device | revoke a device |
| `POST /v1/devices/self/rotate-token` | device | new token, old one dies |
| `GET /v1/status` | device | server time, record count, cursor |

## Development

```sh
uv sync
uv run pytest
```

Layout: `app/main.py` (factory, bootstrap), `routes.py` (endpoints),
`db.py` (tables, transactions), `security.py` (tokens, codes, rate limiter),
`middleware.py` (request IDs, body cap, logging, 500s), `schemas.py`,
`errors.py`, `config.py`, `cli.py`.
