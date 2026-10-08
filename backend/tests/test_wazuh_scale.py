"""Wazuh 在超大規模下（2026-09-30 大量資料測試：3 萬個代理）。

- 代理同步每個代理各查一次鏡像列、兩次 IP：3 萬個代理一輪 15 萬次查詢、334 秒；
  什麼都沒變的一輪也要 6 萬次、155 秒。整輪同步是依序跑的，其他整合全部被它卡住。
- SCA 每一輪對每個代理各打一次 API。Wazuh API 預設每分鐘只收 300 個請求
  （`access.max_request_per_minute`），3 萬個代理光一輪就要 100 分鐘以上，
  中途被限流的請求還會被當成「這台沒有 SCA」安靜略過。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.wazuh import WazuhAgent, WazuhInstance
from app.services import wazuh as wz
from sqlalchemy import event, select


async def _inst(db) -> WazuhInstance:
    inst = WazuhInstance(name=f"wz-{uuid.uuid4().hex[:6]}", api_url="https://mgr.example",
                         api_user="u", api_password_enc=b"x", api_password_nonce=b"y")
    db.add(inst)
    await db.flush()
    return inst


async def _count(db, fn):
    n = {"q": 0}
    conn = await db.connection()

    def _c(*_a, **_k):
        n["q"] += 1
    event.listen(conn.sync_connection, "before_cursor_execute", _c)
    try:
        out = await fn()
        await db.commit()
    finally:
        event.remove(conn.sync_connection, "before_cursor_execute", _c)
    return out, n["q"]


async def test_agent_sync_does_not_query_per_agent(db_session, monkeypatch) -> None:
    db_session.autoflush = False                 # 比照正式環境
    inst = await _inst(db_session)
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="10.60.0.0/16")
    db_session.add(sn)
    await db_session.flush()
    n = 400
    await db_session.execute(IPAddress.__table__.insert(), [
        {"subnet_id": sn.id, "ip": f"10.60.{i // 256}.{i % 256}"} for i in range(1, n + 1)])
    await db_session.commit()
    ka = datetime.now(UTC).replace(microsecond=0)
    agents = [{"id": f"{i:03d}", "name": f"host-{i}", "ip": f"10.60.{i // 256}.{i % 256}", "status": "active",
               "os": {"platform": "ubuntu", "version": "24.04"}, "group": ["default"],
               "lastKeepAlive": ka.isoformat().replace("+00:00", "Z")} for i in range(1, n + 1)]
    agents.append(dict(agents[0]))               # 同一個代理重複出現在回應裡（#43 那一類）

    async def fake(_inst, *, batch=500):
        return agents
    monkeypatch.setattr(wz, "fetch_agents", fake)

    first, q1 = await _count(db_session, lambda: wz.sync_agents(db_session, inst))
    second, q2 = await _count(db_session, lambda: wz.sync_agents(db_session, inst))
    assert (first["new"], first["matched_ip"]) == (n, n)
    assert second["new"] == 0
    assert q1 < 60, f"第一輪查了 {q1} 次（{n} 個代理）"
    assert q2 < 40, f"什麼都沒變的一輪查了 {q2} 次（{n} 個代理）"
    rows = (await db_session.execute(select(WazuhAgent).where(WazuhAgent.instance_id == inst.id))).scalars().all()
    assert len(rows) == n
    ipa = (await db_session.execute(select(IPAddress).where(IPAddress.ip == "10.60.0.7"))).scalar_one()
    assert ipa.hostname == "host-7"
    assert ipa.last_seen_wazuh == ka


async def _agents(db, inst, n, *, checked=None):
    db.add_all([WazuhAgent(instance_id=inst.id, agent_id=f"{i:03d}", status="active", sca_checked_at=checked)
                for i in range(n)])
    await db.commit()


async def test_sca_refresh_is_budgeted_and_oldest_first(db_session, monkeypatch) -> None:
    inst = await _inst(db_session)
    await _agents(db_session, inst, 50)
    asked: list[str] = []

    async def fake(_inst, agent_id):
        asked.append(agent_id)
        return [] if int(agent_id) % 2 else [{"name": "CIS", "score": 60, "pass": 6, "fail": 4}]
    monkeypatch.setattr(wz, "fetch_sca", fake)

    assert await wz.sync_sca(db_session, inst, max_agents=20) == 10
    await db_session.commit()
    assert len(asked) == 20
    first = set(asked)
    asked.clear()
    await wz.sync_sca(db_session, inst, max_agents=20)
    await db_session.commit()
    assert len(asked) == 20
    assert not (first & set(asked)), "每輪要輪到還沒查過的，不是一直查同一批"
    asked.clear()
    await wz.sync_sca(db_session, inst, max_agents=20)
    await wz.sync_sca(db_session, inst, max_agents=20)
    await db_session.commit()
    # 50 個全部查過、都還在更新週期內 → 不再打 API（沒有 SCA 結果的也算查過了）
    assert len(asked) == 10
    empty = (await db_session.execute(select(WazuhAgent).where(
        WazuhAgent.instance_id == inst.id, WazuhAgent.agent_id == "001"))).scalar_one()
    assert empty.sca_score is None
    assert empty.sca_scanned_at is None
    assert empty.sca_checked_at is not None


async def test_sca_stale_agents_are_refreshed(db_session, monkeypatch) -> None:
    inst = await _inst(db_session)
    await _agents(db_session, inst, 3, checked=datetime.now(UTC) - wz.SCA_REFRESH - timedelta(minutes=5))
    asked: list[str] = []

    async def fake(_inst, agent_id):
        asked.append(agent_id)
        return []
    monkeypatch.setattr(wz, "fetch_sca", fake)
    await wz.sync_sca(db_session, inst)
    assert sorted(asked) == ["000", "001", "002"]


async def test_sca_stops_when_rate_limited(db_session, monkeypatch) -> None:
    """被限流就停：後面的請求一樣會被擋，繼續打只會延長被封鎖的時間；沒查到的下一輪再查。"""
    inst = await _inst(db_session)
    await _agents(db_session, inst, 30)
    asked: list[str] = []

    async def fake(_inst, agent_id):
        asked.append(agent_id)
        if len(asked) > 5:
            raise wz.WazuhError("Wazuh GET /sca/x: 429 Too Many Requests")
        return []
    monkeypatch.setattr(wz, "fetch_sca", fake)
    await wz.sync_sca(db_session, inst, max_agents=30)
    await db_session.commit()
    assert len(asked) < 15, f"被限流後還打了 {len(asked)} 次"
    checked = (await db_session.execute(select(WazuhAgent.agent_id).where(
        WazuhAgent.instance_id == inst.id, WazuhAgent.sca_checked_at.is_not(None)))).scalars().all()
    assert len(checked) == 5                     # 被擋下來的不算查過
