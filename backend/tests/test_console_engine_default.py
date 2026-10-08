"""RDP／VNC 的預設引擎改成 guacd（2026-09-27 使用者指示），已安裝的站台也強制改過來。

guacd 沒在跑（例如升級時這個 OS 還沒有預編檔）或沒有這個協定的外掛時，自動退回內建引擎，
而不是讓主控台整個連不上。發票證時決定一次、寫進票證，WebSocket 照票證用 —— 兩邊各自判斷
的話，guacd 剛好在中間起落，瀏覽器講 Guacamole 協定、伺服器講 JSON，畫面只會卡住。
"""
from __future__ import annotations

import json
import uuid

import pytest
from app.services import console_engine
from app.services.system_config import (
    get_rdp_engine,
    get_ssh_engine,
    get_vnc_engine,
    set_rdp_engine,
    set_vnc_engine,
)


def _probe(monkeypatch, protocols: dict[str, bool]) -> None:
    async def fake(*, use_cache: bool = True):
        return {"ok": any(protocols.values()), "address": "127.0.0.1:4822",
                "protocols": protocols, "error": "" if protocols else "connection refused"}
    monkeypatch.setattr("app.services.guacd.probe", fake)


async def test_rdp_and_vnc_default_to_guacd_ssh_stays_builtin(db_session) -> None:
    assert await get_rdp_engine(db_session) == "guacd"
    assert await get_vnc_engine(db_session) == "guacd"
    assert await get_ssh_engine(db_session) == "builtin"


async def test_guacd_is_used_when_it_can_handle_the_protocol(db_session, monkeypatch) -> None:
    _probe(monkeypatch, {"rdp": True, "vnc": True, "ssh": True})
    assert await console_engine.resolve(db_session, "rdp", fallbacks=[("aardwolf", True)]) == "guacd"


async def test_falls_back_when_guacd_is_not_running(db_session, monkeypatch) -> None:
    _probe(monkeypatch, {})
    assert await console_engine.resolve(
        db_session, "rdp", fallbacks=[("aardwolf", False), ("freerdp", True)]) == "freerdp"
    assert await console_engine.resolve(db_session, "vnc", fallbacks=[("builtin", True)]) == "builtin"


async def test_falls_back_when_guacd_lacks_the_protocol(db_session, monkeypatch) -> None:
    _probe(monkeypatch, {"rdp": True, "vnc": False, "ssh": True})
    assert await console_engine.resolve(db_session, "vnc", fallbacks=[("builtin", True)]) == "builtin"


async def test_nothing_to_fall_back_to_keeps_guacd(db_session, monkeypatch) -> None:
    """內建引擎也不能用：照設定用 guacd，錯誤訊息才會講 guacd 的問題（怎麼裝），而不是一個不相干的。"""
    _probe(monkeypatch, {})
    assert await console_engine.resolve(db_session, "vnc", fallbacks=[("builtin", False)]) == "guacd"


async def test_an_explicit_builtin_choice_is_respected(db_session, monkeypatch) -> None:
    """管理者之後自己改回內建：照改的用，不去問 guacd。"""
    _probe(monkeypatch, {"rdp": True, "vnc": True})
    await set_rdp_engine(db_session, engine="aardwolf")
    await set_vnc_engine(db_session, engine="builtin")
    assert await console_engine.resolve(db_session, "rdp", fallbacks=[("aardwolf", True)]) == "aardwolf"
    assert await console_engine.resolve(db_session, "vnc", fallbacks=[("builtin", True)]) == "builtin"


async def test_a_stale_settings_page_does_not_reset_the_rdp_engine(client, auth_headers) -> None:
    """舊版頁面存檔時不帶 rdp_engine：以前會被蓋成 aardwolf（欄位預設值），現在維持原值。"""
    r = await client.put("/api/v1/system/console-security", headers=auth_headers,
                         json={"rdp_clipboard_paste": True})
    assert r.status_code == 200, r.text
    assert r.json()["rdp_engine"] == "guacd"


def test_the_migration_forces_existing_sites_onto_guacd() -> None:
    """已安裝過的站台強制改成 guacd（使用者指示）。SSH 不動。"""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0158_console_engine_guacd.py"
    spec = importlib.util.spec_from_file_location("m0158", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.down_revision == "0157_vpn_tunnel_source_origin"
    assert '"rdp_engine": "guacd"' in mod.FORCE_JSON
    assert '"vnc_engine": "guacd"' in mod.FORCE_JSON
    assert "ssh_engine" not in mod.FORCE_JSON


async def test_the_migration_sql_rewrites_only_rdp_and_vnc(db_session) -> None:
    """實際對資料庫跑一次遷移的 UPDATE：其他設定（剪貼簿、SFTP 上限、SSH 引擎）要留著。"""
    import importlib.util
    from pathlib import Path

    from app.models.system_setting import SystemSetting
    from sqlalchemy import text

    path = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0158_console_engine_guacd.py"
    spec = importlib.util.spec_from_file_location("m0158", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    db_session.add(SystemSetting(key="console_security", value={
        "rdp_engine": "aardwolf", "vnc_engine": "builtin", "ssh_engine": "builtin",
        "rdp_clipboard_paste": True, "sftp_max_file_mb": 500}))
    await db_session.flush()
    await db_session.execute(text(mod.UPGRADE_SQL))
    await db_session.flush()
    db_session.expire_all()
    row = await db_session.get(SystemSetting, "console_security")
    assert row.value == {"rdp_engine": "guacd", "vnc_engine": "guacd", "ssh_engine": "builtin",
                         "rdp_clipboard_paste": True, "sftp_max_file_mb": 500}


# ── 票證帶著決定好的引擎 ──

class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value.encode() if isinstance(value, str) else value

    async def eval(self, _script: str, _numkeys: int, key: str) -> bytes | None:
        return self.store.pop(key, None)


@pytest.fixture
def fake_redis(monkeypatch):
    fake = _FakeRedis()
    for mod in ("rdp_console", "vnc_console"):
        monkeypatch.setattr(f"app.api.v1.endpoints.{mod}._redis_client", lambda: fake)
    monkeypatch.setattr("app.core.rate_limit._redis_client", lambda: fake)
    return fake


async def _console_ip(db_session):
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="198.51.100.9", rdp_enabled=True, vnc_enabled=True)
    db_session.add(ipa)
    await db_session.commit()
    return ipa.id


async def test_the_ticket_records_the_engine_it_was_issued_for(
    client, auth_headers, db_session, fake_redis, monkeypatch,
) -> None:
    from app.api.v1.endpoints import rdp_console, vnc_console

    ip_id = await _console_ip(db_session)
    _probe(monkeypatch, {})                                      # guacd 沒在跑
    monkeypatch.setattr(rdp_console, "RDP_AVAILABLE", True)      # aardwolf 可用
    monkeypatch.setattr(vnc_console, "VNC_AVAILABLE", True)

    r = await client.post(f"/api/v1/addresses/{ip_id}/rdp/ticket", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["engine"] == "aardwolf"
    stored = json.loads(next(v for k, v in fake_redis.store.items() if "rdp" in k))
    assert stored["engine"] == "aardwolf"

    r = await client.post(f"/api/v1/addresses/{ip_id}/vnc/ticket", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["engine"] == "builtin"
    stored = json.loads(next(v for k, v in fake_redis.store.items() if "vnc" in k))
    assert stored["engine"] == "builtin"


async def test_the_websocket_uses_the_engine_from_the_ticket(fake_redis) -> None:
    """guacd 在發票證與連線之間起落：WebSocket 照票證，不自己再判斷一次。"""
    from app.api.v1.endpoints import rdp_console

    ip_id = uuid.uuid4()
    await fake_redis.set(rdp_console._ticket_key("t1"), json.dumps(
        {"user_id": str(uuid.uuid4()), "ip_id": str(ip_id), "engine": "aardwolf"}))
    user_id, engine = await rdp_console._redeem_ticket("t1", ip_id)
    assert user_id is not None
    assert engine == "aardwolf"
