import base64
import json
import uuid

from conftest import auth, b64, change
from test_enroll_auth import assert_error


def push(server, headers, *changes):
    r = server.client.post("/v1/push", json={"changes": list(changes)}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def pull(server, headers, **params):
    r = server.client.get("/v1/pull", params=params, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


# ---- keyslot ---------------------------------------------------------------


def test_keyslot_versioning(device):
    server, headers, _ = device
    assert_error(server.client.get("/v1/keyslot", headers=headers), 404, "not_found")

    r = server.client.put("/v1/keyslot", json={"base_version": 0, "blob": b64(b"slot-1")}, headers=headers)
    assert r.status_code == 200 and r.json() == {"version": 1}
    assert server.client.get("/v1/keyslot", headers=headers).json() == {"version": 1, "blob": b64(b"slot-1")}

    # stale base_version: rejected, current slot returned inside the error
    r = server.client.put("/v1/keyslot", json={"base_version": 0, "blob": b64(b"slot-x")}, headers=headers)
    err = assert_error(r, 409, "version_conflict")
    assert err["current"] == {"version": 1, "blob": b64(b"slot-1")}

    r = server.client.put("/v1/keyslot", json={"base_version": 1, "blob": b64(b"slot-2")}, headers=headers)
    assert r.json() == {"version": 2}
    assert server.client.get("/v1/keyslot", headers=headers).json() == {"version": 2, "blob": b64(b"slot-2")}


def test_keyslot_conflict_when_none_exists(device):
    server, headers, _ = device
    r = server.client.put("/v1/keyslot", json={"base_version": 3, "blob": b64(b"x")}, headers=headers)
    err = assert_error(r, 409, "version_conflict")
    assert err["current"] == {"version": 0, "blob": ""}


def test_keyslot_validation(device):
    server, headers, _ = device
    put = lambda body: server.client.put("/v1/keyslot", json=body, headers=headers)  # noqa: E731
    assert put({"base_version": 0, "blob": b64(b"k" * 16 * 1024)}).status_code == 200
    assert_error(put({"base_version": 1, "blob": b64(b"k" * (16 * 1024 + 1))}), 413, "too_large")
    assert_error(put({"base_version": 1, "blob": "not base64!"}), 422, "invalid_request")
    assert_error(put({"base_version": 1, "blob": ""}), 422, "invalid_request")
    assert_error(put({"base_version": -1, "blob": b64(b"x")}), 422, "invalid_request")
    assert_error(put({"base_version": "1", "blob": b64(b"x")}), 422, "invalid_request")
    assert_error(put({"blob": b64(b"x")}), 422, "invalid_request")


# ---- push / pull -----------------------------------------------------------


def test_push_then_pull_in_seq_order(device):
    server, headers, info = device
    items = [change(f"blob-{i}".encode()) for i in range(5)]
    out = push(server, headers, *items[:3])
    assert out["results"] == [{"id": c["id"], "status": "ok", "seq": i + 1} for i, c in enumerate(items[:3])]
    assert out["cursor"] == 3
    out = push(server, headers, *items[3:])
    assert [r["seq"] for r in out["results"]] == [4, 5] and out["cursor"] == 5

    page = pull(server, headers)
    assert [c["seq"] for c in page["changes"]] == [1, 2, 3, 4, 5]
    assert [c["id"] for c in page["changes"]] == [c["id"] for c in items]
    assert page["cursor"] == 5 and page["has_more"] is False
    first = page["changes"][0]
    assert set(first) == {"id", "seq", "deleted", "blob", "device_id", "updated_at"}
    assert base64.b64decode(first["blob"]) == b"blob-0"
    assert first["deleted"] is False
    assert first["device_id"] == info["device_id"]
    assert abs(first["updated_at"] - int(server.client.get("/healthz").headers["X-Server-Time"])) < 60_000

    assert pull(server, headers, since=3)["changes"][0]["seq"] == 4
    assert pull(server, headers, since=5) == {"changes": [], "cursor": 5, "has_more": False}
    assert pull(server, headers, since=99) == {"changes": [], "cursor": 99, "has_more": False}


def test_update_moves_record_to_end_of_feed(device):
    server, headers, _ = device
    a, b = change(b"a1"), change(b"b1")
    push(server, headers, a, b)
    out = push(server, headers, change(b"a2", base_seq=1, id=a["id"]))
    assert out["results"] == [{"id": a["id"], "status": "ok", "seq": 3}]
    page = pull(server, headers)
    assert [(c["id"], c["seq"]) for c in page["changes"]] == [(b["id"], 2), (a["id"], 3)]
    assert base64.b64decode(page["changes"][1]["blob"]) == b"a2"


def test_paging_and_has_more(device):
    server, headers, _ = device
    push(server, headers, *[change(bytes([i])) for i in range(7)])
    seen, since = [], 0
    for expected_more in (True, True, False):
        page = pull(server, headers, since=since, limit=3)
        assert page["has_more"] is expected_more
        seen += [c["seq"] for c in page["changes"]]
        assert page["cursor"] == seen[-1]
        since = page["cursor"]
    assert seen == [1, 2, 3, 4, 5, 6, 7]
    # an exactly full last page is not "more"
    assert pull(server, headers, since=4, limit=3)["has_more"] is False


def test_pull_page_is_cut_by_size(device, monkeypatch):
    server, headers, _ = device
    monkeypatch.setattr("app.config.PULL_PAGE_BYTES", 250)
    push(server, headers, *[change(b"x" * 100) for _ in range(5)])
    page = pull(server, headers)
    assert [c["seq"] for c in page["changes"]] == [1, 2, 3] and page["has_more"] is True
    page = pull(server, headers, since=page["cursor"])
    assert [c["seq"] for c in page["changes"]] == [4, 5] and page["has_more"] is False


def test_pull_parameter_validation(device):
    server, headers, _ = device
    for params in ({"since": -1}, {"since": "abc"}, {"limit": 0}, {"limit": 501}, {"limit": "x"}):
        assert_error(server.client.get("/v1/pull", params=params, headers=headers), 422, "invalid_request")
    assert server.client.get("/v1/pull", params={"limit": 500}, headers=headers).status_code == 200


def test_conflict_returns_current_blob(device):
    server, headers, info = device
    other = auth(server.enroll(code=server.new_code(info["token"]), name="phone")["token"])
    rec = change(b"v1")
    push(server, headers, rec)
    # both devices edit from seq 1; the first wins
    assert push(server, headers, change(b"v2-laptop", base_seq=1, id=rec["id"]))["results"][0]["seq"] == 2
    out = push(server, other, change(b"v2-phone", base_seq=1, id=rec["id"]))
    assert out["results"] == [
        {"id": rec["id"], "status": "conflict", "seq": 2, "deleted": False, "blob": b64(b"v2-laptop")}
    ]
    assert out["cursor"] == 2
    # nothing was written by the rejected push
    assert base64.b64decode(pull(server, headers)["changes"][0]["blob"]) == b"v2-laptop"
    # after "merging", a re-push on the returned seq is accepted
    out = push(server, other, change(b"v3-merged", base_seq=2, id=rec["id"]))
    assert out["results"] == [{"id": rec["id"], "status": "ok", "seq": 3}]


def test_conflict_cases_for_new_and_unknown_records(device):
    server, headers, _ = device
    rec = change(b"v1")
    push(server, headers, rec)
    # creating a record that already exists (base_seq 0) conflicts
    out = push(server, headers, change(b"dup", id=rec["id"]))
    assert out["results"][0] == {
        "id": rec["id"], "status": "conflict", "seq": 1, "deleted": False, "blob": b64(b"v1"),
    }
    # updating a record the server has never seen: conflict with seq 0, empty blob
    ghost = change(b"ghost", base_seq=7)
    out = push(server, headers, ghost)
    assert out["results"][0] == {
        "id": ghost["id"], "status": "conflict", "seq": 0, "deleted": False, "blob": "",
    }
    assert out["cursor"] == 1


def test_items_are_independent_and_ordered(device):
    server, headers, _ = device
    a, b = change(b"a"), change(b"b")
    push(server, headers, a, b)  # seq 1, 2
    new = change(b"new")
    out = push(
        server,
        headers,
        change(b"a2", base_seq=1, id=a["id"]),  # ok -> 3
        change(b"b-stale", base_seq=1, id=b["id"]),  # conflict (current 2)
        new,  # ok -> 4
        change(b"new2", base_seq=4, id=new["id"]),  # same id again, sees seq 4 -> 5
        change(b"new-stale", base_seq=4, id=new["id"]),  # now stale -> conflict at 5
    )
    assert [(r["status"], r["seq"]) for r in out["results"]] == [
        ("ok", 3), ("conflict", 2), ("ok", 4), ("ok", 5), ("conflict", 5),
    ]
    assert out["results"][1]["blob"] == b64(b"b")
    assert out["results"][4]["blob"] == b64(b"new2")
    assert out["cursor"] == 5
    assert [(c["id"], c["seq"]) for c in pull(server, headers)["changes"]] == [
        (b["id"], 2), (a["id"], 3), (new["id"], 5),
    ]


def test_tombstones(device):
    server, headers, _ = device
    rec = change(b"alive")
    push(server, headers, rec)
    out = push(server, headers, change(b"encrypted-tombstone", base_seq=1, deleted=True, id=rec["id"]))
    assert out["results"] == [{"id": rec["id"], "status": "ok", "seq": 2}]
    page = pull(server, headers)
    assert len(page["changes"]) == 1
    assert page["changes"][0]["deleted"] is True
    assert base64.b64decode(page["changes"][0]["blob"]) == b"encrypted-tombstone"  # blob kept
    # a stale edit against the tombstone gets it back, flagged deleted
    out = push(server, headers, change(b"late edit", base_seq=1, id=rec["id"]))
    assert out["results"][0] == {
        "id": rec["id"], "status": "conflict", "seq": 2, "deleted": True,
        "blob": b64(b"encrypted-tombstone"),
    }
    # tombstones are not counted as records, but the cursor still moved
    status = server.client.get("/v1/status", headers=headers).json()
    assert status["records"] == 0 and status["cursor"] == 2
    # a record can be created directly as a tombstone
    assert push(server, headers, change(b"t", deleted=True))["results"][0]["status"] == "ok"


def test_status(device):
    server, headers, info = device
    r = server.client.get("/v1/status", headers=headers)
    body = r.json()
    assert set(body) == {"server_time", "records", "cursor", "protocol", "vault_id"}
    assert body["records"] == 0 and body["cursor"] == 0 and body["protocol"] == 1
    assert body["vault_id"] == info["vault_id"]
    assert abs(body["server_time"] - int(r.headers["X-Server-Time"])) < 5000
    push(server, headers, change(), change())
    body = server.client.get("/v1/status", headers=headers).json()
    assert body["records"] == 2 and body["cursor"] == 2


def test_empty_push_is_fine(device):
    server, headers, _ = device
    assert push(server, headers) == {"results": [], "cursor": 0}


def test_ids_are_returned_in_canonical_lowercase(device):
    server, headers, _ = device
    rid = str(uuid.uuid4())
    out = push(server, headers, change(id=rid.upper()))
    assert out["results"][0]["id"] == rid
    assert pull(server, headers)["changes"][0]["id"] == rid


# ---- malformed / oversized input ---------------------------------------------


def test_push_malformed(device):
    server, headers, _ = device
    post = lambda body: server.client.post("/v1/push", json=body, headers=headers)  # noqa: E731
    good = change()
    bad_bodies = [
        {},
        {"changes": "nope"},
        {"changes": [good], "unknown": 1},
        {"changes": [{**good, "id": "not-a-uuid"}]},
        {"changes": [{**good, "id": 5}]},
        {"changes": [{**good, "base_seq": -1}]},
        {"changes": [{**good, "base_seq": "0"}]},
        {"changes": [{**good, "base_seq": 1.5}]},
        {"changes": [{**good, "deleted": "false"}]},
        {"changes": [{**good, "deleted": 0}]},
        {"changes": [{**good, "blob": "%%% not base64 %%%"}]},
        {"changes": [{**good, "blob": "YWJj\n"}]},
        {"changes": [{**good, "blob": "YWJjZA"}]},  # missing padding
        {"changes": [{**good, "blob": ""}]},
        {"changes": [{**good, "blob": None}]},
        {"changes": [{**good, "extra": True}]},
        {"changes": [{k: v for k, v in good.items() if k != "deleted"}]},
        [good],
    ]
    for body in bad_bodies:
        assert_error(post(body), 422, "invalid_request")
    r = server.client.post("/v1/push", content=b"\xff\xfe", headers={**headers, "Content-Type": "application/json"})
    assert_error(r, 422, "invalid_request")
    # one bad item rejects the whole request before anything is stored
    assert_error(post({"changes": [change(), {**good, "blob": "!"}]}), 422, "invalid_request")
    assert pull(server, headers)["changes"] == []


def test_push_blob_size_limit(device):
    server, headers, _ = device
    limit = 256 * 1024
    assert push(server, headers, change(b"x" * limit))["results"][0]["status"] == "ok"
    r = server.client.post("/v1/push", json={"changes": [change(b"x" * (limit + 1))]}, headers=headers)
    assert_error(r, 413, "too_large")
    assert base64.b64decode(pull(server, headers)["changes"][0]["blob"]) == b"x" * limit


def test_push_batch_size_limit(device):
    server, headers, _ = device
    out = push(server, headers, *[change(b"x") for _ in range(500)])
    assert out["cursor"] == 500 and len(out["results"]) == 500
    r = server.client.post("/v1/push", json={"changes": [change(b"x") for _ in range(501)]}, headers=headers)
    assert_error(r, 413, "too_large")
    assert server.client.get("/v1/status", headers=headers).json()["cursor"] == 500


def test_body_size_limit_by_content_length(device):
    server, headers, _ = device
    body = json.dumps({"changes": [], "pad": "x" * (8 * 1024 * 1024)}).encode()
    r = server.client.post("/v1/push", content=body, headers={**headers, "Content-Type": "application/json"})
    assert_error(r, 413, "too_large")


def test_body_size_limit_by_actual_bytes(device):
    """Chunked upload with no Content-Length: the bytes themselves are counted."""
    server, headers, _ = device

    def chunks():
        for _ in range(9):
            yield b" " * (1024 * 1024)

    r = server.client.post("/v1/push", content=chunks(), headers={**headers, "Content-Type": "application/json"})
    assert "content-length" not in r.request.headers
    assert_error(r, 413, "too_large")


def test_body_just_under_limit_is_read(device):
    server, headers, _ = device
    # ~7.7 MiB of valid changes: 30 blobs of 192 KiB
    out = push(server, headers, *[change(b"z" * (192 * 1024)) for _ in range(30)])
    assert out["cursor"] == 30


# ---- persistence -------------------------------------------------------------


def test_restart_persistence(device):
    server, headers, info = device
    rec = change(b"survives")
    push(server, headers, rec)
    server.client.put("/v1/keyslot", json={"base_version": 0, "blob": b64(b"slot")}, headers=headers)
    assert server.sql("PRAGMA journal_mode")[0][0] == "wal"

    server.stop()
    server.start()  # brand-new app instance on the same file

    assert server.bootstrap_code is None
    status = server.client.get("/v1/status", headers=headers).json()
    assert status["vault_id"] == info["vault_id"] and status["cursor"] == 1 and status["records"] == 1
    page = pull(server, headers)
    assert page["changes"][0]["id"] == rec["id"]
    assert base64.b64decode(page["changes"][0]["blob"]) == b"survives"
    assert server.client.get("/v1/keyslot", headers=headers).json() == {"version": 1, "blob": b64(b"slot")}
    # the counter carries on, it does not restart
    assert push(server, headers, change(b"next"))["results"][0]["seq"] == 2


def test_concurrent_pushes_get_unique_ordered_seqs(device):
    from concurrent.futures import ThreadPoolExecutor

    from fastapi.testclient import TestClient

    server, headers, _ = device

    def worker(n):
        client = TestClient(server.app)
        seqs = []
        for i in range(10):
            r = client.post("/v1/push", json={"changes": [change(b"%d-%d" % (n, i)), change(b"x")]}, headers=headers)
            assert r.status_code == 200, r.text
            seqs += [item["seq"] for item in r.json()["results"]]
        return seqs

    with ThreadPoolExecutor(8) as pool:
        per_worker = list(pool.map(worker, range(8)))
    all_seqs = sorted(s for seqs in per_worker for s in seqs)
    assert all_seqs == list(range(1, 161))  # no gaps, no duplicates
    assert all(seqs == sorted(seqs) for seqs in per_worker)
    assert [c["seq"] for c in pull(server, headers, limit=500)["changes"]] == all_seqs
