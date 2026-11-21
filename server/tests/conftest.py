import base64
import re
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

CODE_RE = re.compile(r"Enrollment code: ([A-Z2-9]{5}-[A-Z2-9]{5})")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def change(blob: bytes = b"blob", base_seq: int = 0, deleted: bool = False, id: str | None = None):
    return {"id": id or str(uuid.uuid4()), "base_seq": base_seq, "deleted": deleted, "blob": b64(blob)}


class Server:
    """A running app on a temp DB plus helpers the tests share."""

    def __init__(self, db_path, capsys, **overrides):
        self.db_path = str(db_path)
        self.capsys = capsys
        self.overrides = {"rate_limit": False, **overrides}
        self.start()

    def start(self):
        """(Re)create the app on the same DB file, as a restart would."""
        self.capsys.readouterr()
        self.app = create_app(Settings(db_path=self.db_path, **self.overrides))
        self.client = TestClient(self.app, raise_server_exceptions=False)
        found = CODE_RE.search(self.capsys.readouterr().out)
        self.bootstrap_code = found.group(1) if found else None

    def stop(self):
        self.app.state.db.close()

    def sql(self, statement, params=()):
        con = sqlite3.connect(self.db_path)
        try:
            rows = con.execute(statement, params).fetchall()
            con.commit()
            return rows
        finally:
            con.close()

    def enroll(self, code=None, name="laptop", platform="linux"):
        code = code or self.bootstrap_code
        r = self.client.post(
            "/v1/enroll", json={"code": code, "device_name": name, "platform": platform}
        )
        assert r.status_code == 201, r.text
        return r.json()

    def new_code(self, token):
        r = self.client.post("/v1/enrollment-codes", headers=auth(token))
        assert r.status_code == 201, r.text
        return r.json()["code"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def make_server(tmp_path, capsys):
    servers = []

    def _make(**overrides):
        server = Server(tmp_path / f"db{len(servers)}" / "sshsync.db", capsys, **overrides)
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.stop()


@pytest.fixture
def server(make_server):
    return make_server()


@pytest.fixture
def device(server):
    """An enrolled device: (server, auth headers, enroll response)."""
    info = server.enroll()
    return server, auth(info["token"]), info
