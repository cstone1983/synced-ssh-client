import logging
import re

from app import cli
from conftest import CODE_RE, auth, b64, change


def test_bootstrap_code_printed_once(server, capsys):
    first = server.bootstrap_code
    assert first
    # restart while that code is still usable: nothing new is printed
    server.stop()
    server.start()
    assert server.bootstrap_code is None
    # once a device exists there is never a bootstrap code
    info = server.enroll(code=first)
    server.stop()
    server.start()
    assert server.bootstrap_code is None
    assert server.client.get("/v1/status", headers=auth(info["token"])).status_code == 200


def test_bootstrap_code_reissued_when_locked_out(server):
    first = server.bootstrap_code
    # the unused code expires with no device enrolled -> a fresh one on restart
    server.sql("UPDATE enrollment_codes SET expires_at = 1")
    server.stop()
    server.start()
    second = server.bootstrap_code
    assert second and second != first
    # every device revoked -> a fresh one on restart
    info = server.enroll(code=second)
    server.client.delete(f"/v1/devices/{info['device_id']}", headers=auth(info["token"]))
    server.stop()
    server.start()
    assert server.bootstrap_code and server.bootstrap_code != second
    # recovery keeps the same vault and data
    assert server.enroll()["vault_id"] == info["vault_id"]


def test_cli_enroll_code(server, capsys, monkeypatch):
    info = server.enroll()
    monkeypatch.setenv("SSHSYNC_DB_PATH", server.db_path)
    capsys.readouterr()
    assert cli.main(["enroll-code"]) == 0
    code = CODE_RE.search(capsys.readouterr().out).group(1)
    assert code != server.bootstrap_code
    again = server.enroll(code=code, name="recovered")
    assert again["vault_id"] == info["vault_id"]


def test_settings_from_env():
    from app.config import Settings

    s = Settings.from_env({})
    assert s.db_path == "/data/sshsync.db" and s.rate_limit and s.code_ttl_seconds == 600
    assert s.trusted_proxies == () and s.log_level == "INFO"
    s = Settings.from_env(
        {
            "SSHSYNC_DB_PATH": "/tmp/x.db",
            "SSHSYNC_TRUSTED_PROXIES": "127.0.0.1, 10.0.0.0/8",
            "SSHSYNC_RATE_LIMIT": "off",
            "SSHSYNC_CODE_TTL_SECONDS": "30",
            "SSHSYNC_LOG_LEVEL": "debug",
        }
    )
    assert s.db_path == "/tmp/x.db" and not s.rate_limit and s.code_ttl_seconds == 30
    assert [str(n) for n in s.trusted_proxies] == ["127.0.0.1/32", "10.0.0.0/8"]
    assert s.log_level == "DEBUG"


def test_logs_and_output_never_contain_secrets(server, caplog, capsys, monkeypatch):
    caplog.set_level(logging.DEBUG)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)  # worst case: SQL echo on
    try:
        client = server.client
        info = server.enroll()
        token = info["token"]
        headers = auth(token)
        capsys.readouterr()  # drop the bootstrap banner; everything after must be clean

        blob = b"SUPER-SECRET-BLOB-" + bytes(range(256))
        keyslot = b"SUPER-SECRET-KEYSLOT"
        rec = change(blob)
        code = server.new_code(token)
        client.put("/v1/keyslot", json={"base_version": 0, "blob": b64(keyslot)}, headers=headers)
        client.get("/v1/keyslot", headers=headers)
        client.post("/v1/push", json={"changes": [rec]}, headers=headers)
        client.post("/v1/push", json={"changes": [rec]}, headers=headers)  # conflict path
        client.get("/v1/pull", headers=headers)
        client.get("/v1/devices", headers=headers)
        # failures: bad code, bad token, invalid body carrying a blob, forced 500
        client.post("/v1/enroll", json={"code": "ZZZZZ-ZZZZZ", "device_name": "x", "platform": "linux"})
        client.get("/v1/status", headers=auth("BOGUS-TOKEN-VALUE"))
        client.post("/v1/push", json={"changes": [{**rec, "base_seq": "x"}]}, headers=headers)

        def boom(*a, **k):
            raise RuntimeError(f"boom {token} {b64(blob)}")

        monkeypatch.setattr("app.routes.get_seq", boom)
        assert client.get("/v1/status", headers=headers).status_code == 500
        monkeypatch.undo()

        phone = server.enroll(code=code, name="phone", platform="android")
        new_token = client.post("/v1/devices/self/rotate-token", headers=headers).json()["token"]
        client.delete(f"/v1/devices/{phone['device_id']}", headers=auth(new_token))
        client.get("/v1/status", headers=auth(phone["token"]))  # device_revoked
    finally:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    captured = capsys.readouterr()
    text = caplog.text + captured.out + captured.err
    assert "Logging error" not in captured.err
    assert "POST /v1/push 200" in captured.out  # the real stdout handler ran too
    app_lines = [r.getMessage() for r in caplog.records if r.name == "sshsync"]

    # the request log is there and useful...
    assert any(re.search(r"POST /v1/push 200 device=%s request_id=\w+ in=\d+ out=\d+" % info["device_id"], l)
               for l in app_lines)
    assert any("GET /v1/status 500" in l for l in app_lines)
    assert any(l.startswith("unhandled RuntimeError") for l in app_lines)
    assert any("GET /v1/status 401 device=%s" % phone["device_id"] in l for l in app_lines)

    # ...and holds none of the secrets, in any encoding we handle
    secrets = [
        token, new_token, phone["token"], "BOGUS-TOKEN-VALUE",
        code, code.replace("-", ""), "ZZZZZ-ZZZZZ", "ZZZZZZZZZZ",
        server.bootstrap_code, server.bootstrap_code.replace("-", ""),
        b64(blob), b64(keyslot), "SUPER-SECRET", blob.hex(), keyslot.hex(),
    ]
    for secret in secrets:
        assert secret not in text, f"leaked: {secret[:12]}..."
