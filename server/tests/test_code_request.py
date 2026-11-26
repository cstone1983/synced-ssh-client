"""POST /v1/enrollment-codes/request: a code sent to the owner, never returned."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.config import Settings
from app.notify import NotifyError, make_notifier, webhook_notifier
from conftest import auth

BODY = {"device_name": "Pixel Fold", "platform": "android"}


class Inbox:
    """Stands in for the n8n webhook."""

    def __init__(self):
        self.sent = []
        self.fail = None

    def __call__(self, payload):
        if self.fail:
            raise self.fail
        self.sent.append(payload)


@pytest.fixture
def inbox():
    return Inbox()


@pytest.fixture
def notifying(make_server, inbox):
    server = make_server()
    server.app.state.notify = inbox
    return server


def request_code(server, body=BODY, **kw):
    return server.client.post("/v1/enrollment-codes/request", json=body, **kw)


def test_code_is_sent_not_returned_and_enrolls(notifying, inbox):
    r = request_code(notifying)
    assert r.status_code == 202, r.text
    assert set(r.json()) == {"sent", "expires_at"}
    assert inbox.sent and inbox.sent[0]["code"] not in r.text
    sent = inbox.sent[0]
    assert sent["device_name"] == "Pixel Fold"
    assert sent["platform"] == "android"
    assert sent["expires_minutes"] == 10
    assert sent["ip"]
    info = notifying.enroll(code=sent["code"], name="Pixel Fold", platform="android")
    assert info["token"]


def test_requested_code_is_single_use(notifying, inbox):
    request_code(notifying)
    code = inbox.sent[0]["code"]
    notifying.enroll(code=code)
    r = notifying.client.post(
        "/v1/enroll", json={"code": code, "device_name": "x", "platform": "other"}
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_code"


def test_requested_code_expires(notifying, inbox):
    request_code(notifying)
    notifying.sql("UPDATE enrollment_codes SET expires_at = 1")
    r = notifying.client.post(
        "/v1/enroll", json={"code": inbox.sent[0]["code"], "device_name": "x", "platform": "other"}
    )
    assert r.status_code == 401


def test_reply_does_not_depend_on_enrolled_devices(notifying, inbox):
    before = request_code(notifying)
    notifying.enroll()
    after = request_code(notifying)
    assert before.status_code == after.status_code == 202
    assert set(before.json()) == set(after.json())


def test_needs_no_token_and_ignores_one(notifying, inbox):
    r = request_code(notifying, headers=auth("not-a-real-token"))
    assert r.status_code == 202
    assert len(inbox.sent) == 1


def test_off_when_not_configured(server):
    r = request_code(server)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_available"
    assert len(server.sql("SELECT * FROM enrollment_codes")) == 1  # just the bootstrap code


@pytest.mark.parametrize("fail", [NotifyError("webhook answered 500"), ValueError("boom")])
def test_failed_delivery_leaves_no_usable_code(notifying, inbox, fail):
    count = len(notifying.sql("SELECT * FROM enrollment_codes"))
    inbox.fail = fail
    r = request_code(notifying)
    assert r.status_code == 502
    assert r.json()["error"]["code"] == "notify_failed"
    assert len(notifying.sql("SELECT * FROM enrollment_codes")) == count


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"device_name": "", "platform": "android"},
        {"device_name": "x" * 65, "platform": "android"},
        {"device_name": "x", "platform": "ios"},
        {**BODY, "code": "AAAAA-AAAAA"},
    ],
)
def test_rejects_bad_body(notifying, inbox, body):
    assert request_code(notifying, body=body).status_code == 422
    assert not inbox.sent


def test_rate_limit_per_address(make_server, inbox):
    server = make_server(rate_limit=True, code_request_per_minute=2, code_request_per_hour=50)
    server.app.state.notify = inbox
    assert [request_code(server).status_code for _ in range(3)] == [202, 202, 429]
    assert len(inbox.sent) == 2


def test_rate_limit_in_total_per_hour(make_server, inbox):
    server = make_server(rate_limit=True, code_request_per_minute=50, code_request_per_hour=2)
    server.app.state.notify = inbox
    statuses = [
        request_code(server, headers={"X-Forwarded-For": f"10.0.0.{i}"}).status_code
        for i in range(3)
    ]
    assert statuses == [202, 202, 429]
    assert len(inbox.sent) == 2


def test_code_never_logged(notifying, inbox, capsys):
    capsys.readouterr()
    request_code(notifying)
    out = capsys.readouterr()
    assert inbox.sent[0]["code"] not in out.out + out.err


def test_make_notifier_needs_url_and_key():
    assert make_notifier(Settings()) is None
    assert make_notifier(Settings(notify_url="http://n8n:5678/webhook/x")) is None
    assert make_notifier(Settings(notify_url="ftp://x", notify_key="k")) is None
    assert make_notifier(Settings(notify_url="http://n8n:5678/webhook/x", notify_key="k")) is not None


def test_settings_read_key_from_file(tmp_path):
    key = tmp_path / "key"
    key.write_text("s3cret\n")
    s = Settings.from_env({"SSHSYNC_NOTIFY_URL": " http://n8n/x ", "SSHSYNC_NOTIFY_KEY_FILE": str(key)})
    assert (s.notify_url, s.notify_key) == ("http://n8n/x", "s3cret")
    assert Settings.from_env({"SSHSYNC_NOTIFY_KEY": "k2"}).notify_key == "k2"


class _Hook(BaseHTTPRequestHandler):
    status = 200
    received: list = []

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        type(self).received.append((dict(self.headers), json.loads(self.rfile.read(length))))
        self.send_response(type(self).status)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def hook():
    _Hook.received = []
    _Hook.status = 200
    httpd = HTTPServer(("127.0.0.1", 0), _Hook)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def test_webhook_notifier_posts_json_with_key(hook):
    url = f"http://127.0.0.1:{hook.server_port}/webhook/sshsync"
    webhook_notifier(url, "the-key")({"code": "ABCDE-FGHJK"})
    headers, body = _Hook.received[0]
    assert headers["X-Sshsync-Key"] == "the-key"
    assert headers["Content-Type"] == "application/json"
    assert body == {"code": "ABCDE-FGHJK"}


def test_webhook_notifier_raises_on_error_status(hook):
    _Hook.status = 403
    url = f"http://127.0.0.1:{hook.server_port}/webhook/sshsync"
    with pytest.raises(NotifyError, match="403"):
        webhook_notifier(url, "k")({"code": "x"})


def test_webhook_notifier_raises_when_unreachable(hook):
    port = hook.server_port
    hook.shutdown()
    hook.server_close()
    with pytest.raises(NotifyError, match="unreachable"):
        webhook_notifier(f"http://127.0.0.1:{port}/x", "k")({"code": "x"})
