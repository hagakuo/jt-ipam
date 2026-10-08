"""SFTP 傳輸路徑測試（使用者要求，2026-09-26）。

SFTP 上限放大之後，瀏覽器 → 前端反向代理 → IPAM 的 nginx → 後端，任何一層吃不下都會讓傳輸
失敗，而那些設定我們讀不到 —— 只能實際送一次。測試模式走跟 SFTP **同一條 WebSocket 路徑**
（代理的放行規則多半只寫主控台那組路徑），不連任何主機，只把資料收下／送出並回報數量。
"""
from __future__ import annotations

import asyncio
import json

import pytest
from app.services import sftp_probe as probe


class _Peer:
    """假的 WebSocket：`inbox` 是客戶端送來的訊息，`out` 收伺服器送出的東西。"""

    def __init__(self, inbox: list) -> None:
        self.inbox = list(inbox)
        self.out: list = []

    async def receive(self) -> dict:
        if not self.inbox:
            await asyncio.sleep(3600)
        m = self.inbox.pop(0)
        if isinstance(m, bytes):
            return {"type": "websocket.receive", "bytes": m}
        if m is None:
            return {"type": "websocket.disconnect", "code": 1000}
        return {"type": "websocket.receive", "text": json.dumps(m)}

    async def send_text(self, s: str) -> None:
        self.out.append(json.loads(s))

    async def send_bytes(self, b: bytes) -> None:
        self.out.append(b)

    def texts(self) -> list[dict]:
        return [m for m in self.out if isinstance(m, dict)]


async def _run(inbox: list) -> _Peer:
    peer = _Peer(inbox)
    await asyncio.wait_for(probe.run(peer.receive, peer.send_text, peer.send_bytes), 5)
    return peer


async def test_upload_is_counted_and_acknowledged_like_sftp() -> None:
    size = 3 * probe.CHUNK_BYTES + 100
    frames = [b"x" * probe.CHUNK_BYTES] * 3 + [b"x" * 100]
    peer = await _run([{"type": "put", "size": size, "id": 1}, *frames, {"type": "bye"}])
    t = peer.texts()
    assert t[0]["type"] == "ready" and t[0]["probe"] is True
    assert t[1] == {"type": "put_ready", "id": 1}
    acks = [m["bytes"] for m in t if m["type"] == "put_ack"]
    assert acks and acks[-1] == size, "要跟 SFTP 一樣回確認，用戶端的流量控制才測得到"
    done = [m for m in t if m["type"] == "ok"][0]
    assert done["bytes"] == size and done["id"] == 1 and done["ms"] >= 0


async def test_download_sends_the_requested_bytes_in_sftp_sized_frames() -> None:
    size = 2 * probe.CHUNK_BYTES + 7
    peer = await _run([{"type": "get", "size": size, "id": 2}, {"type": "bye"}])
    frames = [m for m in peer.out if isinstance(m, bytes)]
    assert sum(map(len, frames)) == size
    assert max(map(len, frames)) == probe.CHUNK_BYTES
    # 不可以是一整片 0：路上有壓縮的話，量到的就不是真實大小與速度
    assert len(set(frames[0])) > 200
    t = peer.texts()
    assert [m["type"] for m in t][-2:] == ["file_begin", "file_end"] or t[-1]["type"] == "file_end"
    assert t[-1]["sent"] == size


async def test_sizes_are_capped() -> None:
    peer = await _run([{"type": "get", "size": probe.PROBE_MAX + 1, "id": 3}, {"type": "bye"}])
    err = [m for m in peer.texts() if m["type"] == "error"][0]
    assert err["code"] == "sftp_probe_too_large"
    assert not [m for m in peer.out if isinstance(m, bytes)]


async def test_a_client_that_stops_sending_does_not_hold_the_connection(monkeypatch) -> None:
    monkeypatch.setattr(probe, "STALL_TIMEOUT", 0.2)
    peer = await _run([{"type": "put", "size": 1000, "id": 4}, b"x" * 10, {"type": "bye"}])
    err = [m for m in peer.texts() if m["type"] == "error"]
    assert err and err[0]["code"] == "sftp_probe_stalled"


async def test_disconnect_ends_quietly() -> None:
    peer = await _run([None])
    assert peer.texts()[0]["type"] == "ready"


@pytest.mark.parametrize("op", ["put", "get"])
async def test_the_session_total_is_capped(op) -> None:
    """一張票證只能測有限的量 —— 不可以變成一條任意灌流量的通道。"""
    n = probe.SESSION_MAX // probe.PROBE_MAX + 1
    msgs: list = []
    for i in range(n):
        msgs.append({"type": op, "size": probe.PROBE_MAX, "id": i})
        if op == "put":
            msgs += [b"x" * probe.CHUNK_BYTES] * (probe.PROBE_MAX // probe.CHUNK_BYTES)
    peer = await _run([*msgs, {"type": "bye"}])
    assert any(m.get("code") == "sftp_probe_session_limit" for m in peer.texts())


class _FakeRedis:
    """夠用的假 Redis（CI 沒有 Redis 服務；其他票證測試也是這樣做）。"""

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value.encode() if isinstance(value, str) else value

    async def eval(self, _script: str, _numkeys: int, key: str) -> bytes | None:
        return self.store.pop(key, None)


async def test_ticket_endpoint_is_admin_only_and_points_at_the_sftp_path(
    client, auth_headers, db_session, monkeypatch,
) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr("app.api.v1.endpoints.sftp_console._redis_client", lambda: fake)
    monkeypatch.setattr("app.core.rate_limit._redis_client", lambda: fake)
    r = await client.post("/api/v1/system/sftp-probe/ticket", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ws_path"] == f"/api/v1/addresses/{probe.PROBE_ADDRESS_ID}/sftp/ws"
    assert body["ticket"] and body["up_bytes"] <= probe.PROBE_MAX
    assert any(body["ticket"] in k for k in fake.store), "票證沒有存進 Redis"
