import re
import uuid

from conftest import auth


def assert_error(r, status, code):
    assert r.status_code == status, r.text
    body = r.json()
    assert body["error"]["code"] == code
    assert isinstance(body["error"]["message"], str)
    assert r.headers["X-Request-Id"]
    assert int(r.headers["X-Server-Time"]) > 1_600_000_000_000
    return body["error"]


def test_healthz_needs_no_auth(server):
    r = server.client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert r.headers["X-Request-Id"] and r.headers["X-Server-Time"].isdigit()


def test_bootstrap_code_format(server):
    assert re.fullmatch(r"[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{5}-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{5}",
                        server.bootstrap_code)


def test_enroll_valid(server):
    info = server.enroll(name="Pixel", platform="android")
    assert set(info) == {"device_id", "token", "vault_id", "protocol"}
    assert info["protocol"] == 1
    uuid.UUID(info["device_id"]), uuid.UUID(info["vault_id"])
    assert len(info["token"]) == 43
    r = server.client.get("/v1/status", headers=auth(info["token"]))
    assert r.status_code == 200
    assert r.json()["vault_id"] == info["vault_id"]


def test_enroll_accepts_lowercase_spaces_and_no_dash(server):
    sloppy = server.bootstrap_code.replace("-", " ").lower()
    server.enroll(code=f" {sloppy} ")


def test_enroll_code_is_single_use(server):
    server.enroll()
    r = server.client.post(
        "/v1/enroll",
        json={"code": server.bootstrap_code, "device_name": "x", "platform": "other"},
    )
    assert_error(r, 401, "invalid_code")


def test_enroll_wrong_code(server):
    r = server.client.post(
        "/v1/enroll", json={"code": "AAAAA-AAAAA", "device_name": "x", "platform": "linux"}
    )
    assert_error(r, 401, "invalid_code")
    # the real code still works afterwards
    server.enroll()


def test_enroll_expired_code(server):
    server.sql("UPDATE enrollment_codes SET expires_at = 1")
    r = server.client.post(
        "/v1/enroll",
        json={"code": server.bootstrap_code, "device_name": "x", "platform": "linux"},
    )
    assert_error(r, 401, "invalid_code")


def test_code_ttl_is_configurable(make_server):
    server = make_server(code_ttl_seconds=1234)
    created, expires = server.sql("SELECT created_at, expires_at FROM enrollment_codes")[0]
    assert expires - created == 1234 * 1000


def test_enroll_malformed(server):
    post = lambda body, **kw: server.client.post("/v1/enroll", json=body, **kw)  # noqa: E731
    good = {"code": server.bootstrap_code, "device_name": "x", "platform": "linux"}
    # a code of the wrong shape is simply an invalid code
    assert_error(post({**good, "code": "not a code!"}), 401, "invalid_code")
    assert_error(post({**good, "code": ""}), 401, "invalid_code")
    # structural problems are validation errors
    assert_error(post({**good, "platform": "ios"}), 422, "invalid_request")
    assert_error(post({**good, "device_name": ""}), 422, "invalid_request")
    assert_error(post({**good, "device_name": "n" * 65}), 422, "invalid_request")
    assert_error(post({**good, "code": 12345}), 422, "invalid_request")
    assert_error(post({**good, "extra": 1}), 422, "invalid_request")
    assert_error(post({"code": good["code"]}), 422, "invalid_request")
    assert_error(post([1, 2]), 422, "invalid_request")
    r = server.client.post(
        "/v1/enroll", content=b"{not json", headers={"Content-Type": "application/json"}
    )
    assert_error(r, 422, "invalid_request")
    # none of that burned the code
    server.enroll()


def test_validation_error_does_not_echo_input(server):
    r = server.client.post(
        "/v1/enroll",
        json={"code": "SECRETCODE", "device_name": "x", "platform": "SECRET-PLATFORM"},
    )
    assert_error(r, 422, "invalid_request")
    assert "SECRET" not in r.text


def test_enroll_rate_limited(make_server):
    server = make_server(rate_limit=True)
    body = {"code": "AAAAA-AAAAA", "device_name": "x", "platform": "linux"}
    for _ in range(5):
        assert_error(server.client.post("/v1/enroll", json=body), 401, "invalid_code")
    r = server.client.post("/v1/enroll", json={**body, "code": server.bootstrap_code})
    assert_error(r, 429, "rate_limited")
    assert r.headers["Retry-After"] == "60"


def test_rate_limit_keys_on_forwarded_for_only_from_trusted_proxy(make_server):
    from app.config import parse_networks

    body = {"code": "AAAAA-AAAAA", "device_name": "x", "platform": "linux"}
    # TestClient's peer address is "testclient", so trust it by... not trusting:
    untrusted = make_server(rate_limit=True)
    for i in range(5):
        untrusted.client.post("/v1/enroll", json=body, headers={"X-Forwarded-For": f"10.0.0.{i}"})
    r = untrusted.client.post("/v1/enroll", json=body, headers={"X-Forwarded-For": "10.0.0.99"})
    assert_error(r, 429, "rate_limited")  # spoofed header ignored: all one bucket

    from app.security import client_ip

    nets = parse_networks("127.0.0.1, 172.16.0.0/12")
    assert client_ip("127.0.0.1", "1.2.3.4", nets) == "1.2.3.4"
    assert client_ip("127.0.0.1", "6.6.6.6, 1.2.3.4, 172.18.0.1", nets) == "1.2.3.4"
    assert client_ip("8.8.8.8", "1.2.3.4", nets) == "8.8.8.8"
    assert client_ip("127.0.0.1", None, nets) == "127.0.0.1"
    assert client_ip("127.0.0.1", "garbage", nets) == "127.0.0.1"
    assert client_ip("127.0.0.1", "1.2.3.4", ()) == "127.0.0.1"


def test_auth_required_everywhere_under_v1(server):
    calls = [
        ("POST", "/v1/enrollment-codes"),
        ("GET", "/v1/keyslot"),
        ("PUT", "/v1/keyslot"),
        ("POST", "/v1/push"),
        ("GET", "/v1/pull"),
        ("GET", "/v1/devices"),
        ("DELETE", f"/v1/devices/{uuid.uuid4()}"),
        ("POST", "/v1/devices/self/rotate-token"),
        ("GET", "/v1/status"),
    ]
    for method, path in calls:
        r = server.client.request(method, path)
        assert_error(r, 401, "unauthorized")
        assert r.headers["WWW-Authenticate"] == "Bearer"
        r = server.client.request(method, path, headers=auth("wrong-token"))
        assert_error(r, 401, "unauthorized")
        r = server.client.request(method, path, headers={"Authorization": "Basic abc"})
        assert_error(r, 401, "unauthorized")


def test_failed_auth_rate_limited(make_server):
    server = make_server(rate_limit=True)
    info = server.enroll()
    for _ in range(10):
        assert_error(server.client.get("/v1/status", headers=auth("nope")), 401, "unauthorized")
    assert_error(server.client.get("/v1/status", headers=auth("nope")), 429, "rate_limited")
    # a valid token is not locked out by someone else's failures
    assert server.client.get("/v1/status", headers=auth(info["token"])).status_code == 200


def test_authenticated_traffic_rate_limited_per_device(make_server):
    server = make_server(rate_limit=True, device_per_minute=3)
    a = auth(server.enroll()["token"])
    b = auth(server.enroll(code=server.new_code(a["Authorization"][7:]))["token"])
    statuses = [server.client.get("/v1/status", headers=a).status_code for _ in range(3)]
    assert statuses == [200, 200, 429]  # new_code used one of a's three
    assert server.client.get("/v1/status", headers=b).status_code == 200


def test_token_stored_only_as_hash(device):
    server, _, info = device
    dump = repr(server.sql("SELECT * FROM devices")) + repr(server.sql("SELECT * FROM enrollment_codes"))
    assert info["token"] not in dump
    assert server.bootstrap_code not in dump
    assert server.bootstrap_code.replace("-", "") not in dump


def test_enrollment_codes_endpoint(device):
    server, headers, _ = device
    r = server.client.post("/v1/enrollment-codes", headers=headers)
    assert r.status_code == 201
    body = r.json()
    assert re.fullmatch(r"[A-Z2-9]{5}-[A-Z2-9]{5}", body["code"])
    ttl = body["expires_at"] - int(r.headers["X-Server-Time"])
    assert 590_000 < ttl <= 600_000
    second = server.enroll(code=body["code"], name="phone", platform="android")
    assert second["vault_id"] == device[2]["vault_id"]
    assert second["device_id"] != device[2]["device_id"]


def test_devices_list_and_last_seen(device):
    server, headers, info = device
    other = server.enroll(code=server.new_code(info["token"]), name="phone", platform="android")
    server.sql("UPDATE devices SET last_seen_at = 5 WHERE id = ?", (info["device_id"],))
    r = server.client.get("/v1/devices", headers=headers)
    assert r.status_code == 200
    devices = {d["id"]: d for d in r.json()["devices"]}
    assert set(devices) == {info["device_id"], other["device_id"]}
    me = devices[info["device_id"]]
    assert set(me) == {"id", "name", "platform", "created_at", "last_seen_at", "revoked", "current"}
    assert me["current"] is True and me["revoked"] is False
    assert me["name"] == "laptop" and me["platform"] == "linux"
    assert me["last_seen_at"] > 5  # bumped by this very request
    assert devices[other["device_id"]]["current"] is False


def test_revocation(device):
    server, headers, info = device
    other = server.enroll(code=server.new_code(info["token"]), name="phone", platform="android")
    r = server.client.delete(f"/v1/devices/{other['device_id']}", headers=headers)
    assert r.status_code == 200 and r.json() == {"revoked": True}
    # token dies immediately, with the dedicated code
    for path in ("/v1/status", "/v1/pull", "/v1/devices"):
        assert_error(server.client.get(path, headers=auth(other["token"])), 401, "device_revoked")
    # the row is kept and shown as revoked
    devices = {d["id"]: d for d in server.client.get("/v1/devices", headers=headers).json()["devices"]}
    assert devices[other["device_id"]]["revoked"] is True
    # revoking again is harmless; unknown / malformed ids are errors
    assert server.client.delete(f"/v1/devices/{other['device_id']}", headers=headers).status_code == 200
    assert_error(server.client.delete(f"/v1/devices/{uuid.uuid4()}", headers=headers), 404, "not_found")
    assert_error(server.client.delete("/v1/devices/not-a-uuid", headers=headers), 422, "invalid_request")


def test_device_may_revoke_itself(device):
    server, headers, info = device
    r = server.client.delete(f"/v1/devices/{info['device_id']}", headers=headers)
    assert r.json() == {"revoked": True}
    assert_error(server.client.get("/v1/status", headers=headers), 401, "device_revoked")


def test_token_rotation(device):
    server, headers, info = device
    r = server.client.post("/v1/devices/self/rotate-token", headers=headers)
    assert r.status_code == 200
    new = r.json()["token"]
    assert new != info["token"] and len(new) == 43
    assert_error(server.client.get("/v1/status", headers=headers), 401, "unauthorized")
    r = server.client.get("/v1/devices", headers=auth(new))
    assert [d["id"] for d in r.json()["devices"] if d["current"]] == [info["device_id"]]


def test_unknown_route_and_method(server):
    assert_error(server.client.get("/nope"), 404, "not_found")
    assert_error(server.client.delete("/healthz"), 405, "method_not_allowed")


def test_unexpected_exception_becomes_json_500(device, monkeypatch):
    server, headers, _ = device

    def boom(*a, **k):
        raise RuntimeError("secret detail that must not leak")

    monkeypatch.setattr("app.routes.get_seq", boom)
    r = server.client.get("/v1/status", headers=headers)
    err = assert_error(r, 500, "internal")
    assert err["request_id"] == r.headers["X-Request-Id"]
    assert "secret detail" not in r.text and "Traceback" not in r.text
