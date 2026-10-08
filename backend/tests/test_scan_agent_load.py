"""掃描代理負載：每輪自動記錄耗時、評估負載、太重時通知管理員並給出具體建議（2026-09-28 使用者要求）。

- 「太長」分兩種：上線偵測一輪超過週期（上線狀態會延遲）、背景重量探測一直消化不完（資料變舊）
- 連續 3 輪才算，恢復時也通知一次（沿用 state_alert，不洗版）
- 建議要能直接照做：移哪幾個子網路、哪個子網路特別慢（多半跨 WAN）、哪個子網路被截斷
- 不自動搬子網路：系統不知道哪台代理跟哪個網段在同一層，自動搬會讓資料默默變差
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.scan_agent import ScanAgent
from app.services import scan_load
from sqlalchemy import select


def _cycle(duration, interval=300, backlog=0, subnets=None):
    return {"duration_s": duration, "interval_s": interval, "heavy_backlog": backlog,
            "subnets": subnets or [{"cidr": "198.51.100.0/24", "hosts": 254, "total_hosts": 254,
                                    "alive": 50, "duration_s": duration, "truncated": False}]}


def test_load_levels() -> None:
    assert scan_load.evaluate(_cycle(30))["level"] == "ok"
    assert scan_load.evaluate(_cycle(200))["level"] == "busy"
    assert scan_load.evaluate(_cycle(290))["level"] == "overloaded"
    assert scan_load.evaluate(_cycle(290))["ratio"] == round(290 / 300, 3)


def test_overloaded_agent_gets_told_which_subnets_to_move() -> None:
    subs = [{"cidr": f"198.51.{i}.0/24", "hosts": 254, "total_hosts": 254, "alive": 10,
             "duration_s": d, "truncated": False} for i, d in enumerate([150, 90, 40, 20])]
    ev = scan_load.evaluate(_cycle(300, subnets=subs))
    move = next(s for s in ev["suggestions"] if s["code"] == "move_subnets")
    # 移掉最慢的那個就能降到 70% 以下（300-150=150 → 50%）
    assert move["params"]["subnets"] == ["198.51.0.0/24"]


def test_a_subnet_much_slower_per_host_is_called_out() -> None:
    subs = [{"cidr": "198.51.100.0/24", "hosts": 254, "total_hosts": 254, "alive": 10, "duration_s": 3,
             "truncated": False},
            {"cidr": "203.0.113.0/24", "hosts": 254, "total_hosts": 254, "alive": 10, "duration_s": 40,
             "truncated": False},
            {"cidr": "192.0.2.0/24", "hosts": 254, "total_hosts": 254, "alive": 10, "duration_s": 4,
             "truncated": False}]
    ev = scan_load.evaluate(_cycle(47, subnets=subs))
    slow = [s for s in ev["suggestions"] if s["code"] == "slow_subnet"]
    assert [s["params"]["cidr"] for s in slow] == ["203.0.113.0/24"]


def test_truncated_subnet_is_reported() -> None:
    subs = [{"cidr": "198.18.0.0/16", "hosts": 1024, "total_hosts": 65534, "alive": 300, "duration_s": 20,
             "truncated": True}]
    ev = scan_load.evaluate(_cycle(20, subnets=subs))
    assert ev["truncated"] == ["198.18.0.0/16"]
    big = next(s for s in ev["suggestions"] if s["code"] == "split_large")
    assert big["params"] == {"cidr": "198.18.0.0/16", "total": 65534, "scanned": 1024}


def test_heavy_backlog_that_never_shrinks_is_lagging() -> None:
    hist = [{"heavy_backlog": b} for b in (120, 130, 150, 160, 170, 180)]
    ev = scan_load.evaluate(_cycle(20, backlog=180), history=hist)
    assert ev["heavy_lagging"] is True
    assert any(s["code"] == "heavy_interval" for s in ev["suggestions"])
    shrinking = [{"heavy_backlog": b} for b in (180, 150, 120, 90, 60, 30)]
    assert scan_load.evaluate(_cycle(20, backlog=30), history=shrinking)["heavy_lagging"] is False


# ─────────────────── 端點＋告警 ───────────────────

async def _agent(db):
    from app.api.v1.endpoints.scan_agents import _key_hash
    raw = "l" * 40
    agent = ScanAgent(name=f"agent-{uuid.uuid4().hex[:6]}", enroll_key_hash=_key_hash(raw), enabled=True)
    db.add(agent)
    await db.commit()
    return raw, agent


async def _report(client, raw, cycle):
    r = await client.post("/api/v1/scan-agents/report", headers={"X-Agent-Key": raw},
                          json={"results": [], "cycle": cycle})
    assert r.status_code == 200, r.text


async def test_every_cycle_is_recorded_and_old_ones_pruned(client, db_session) -> None:
    from app.models.scan_agent_cycle import ScanAgentCycle
    raw, agent = await _agent(db_session)
    db_session.add(ScanAgentCycle(agent_id=agent.id, at=datetime.now(UTC) - timedelta(days=8),
                                  duration_s=1, interval_s=300, heavy_backlog=0))
    await db_session.commit()
    await _report(client, raw, _cycle(12))
    await _report(client, raw, _cycle(14))
    rows = (await db_session.execute(select(ScanAgentCycle).where(
        ScanAgentCycle.agent_id == agent.id).order_by(ScanAgentCycle.at))).scalars().all()
    assert [r.duration_s for r in rows] == [12, 14]          # 8 天前那筆被清掉


async def test_three_overloaded_cycles_notify_admins_once_and_recovery_too(client, db_session, admin_user) -> None:
    from app.models.notification import Notification
    raw, agent = await _agent(db_session)

    async def notes():
        return (await db_session.execute(select(Notification).where(
            Notification.user_id == admin_user.id,
            Notification.title_key.in_(["notif.agent_overloaded", "notif.agent_overload_ok"])))).scalars().all()

    await _report(client, raw, _cycle(295))
    await _report(client, raw, _cycle(295))
    assert await notes() == []                               # 偶發不吵
    await _report(client, raw, _cycle(295))
    await _report(client, raw, _cycle(295))
    got = await notes()
    assert [n.title_key for n in got] == ["notif.agent_overloaded"]   # 第三輪發一次，之後不重發
    assert got[0].params["agent"] == agent.name
    assert got[0].link == f"/scan-agents?load={agent.id}"
    await _report(client, raw, _cycle(20))
    assert [n.title_key for n in await notes()] == ["notif.agent_overloaded", "notif.agent_overload_ok"]


async def test_load_detail_endpoint(client, auth_headers, db_session) -> None:
    raw, agent = await _agent(db_session)
    for d in (10, 20, 30):
        await _report(client, raw, _cycle(d))
    r = await client.get(f"/api/v1/scan-agents/{agent.id}/load", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["evaluation"]["level"] == "ok"
    assert [h["duration_s"] for h in body["history"]] == [10, 20, 30]
    assert body["last_cycle"]["duration_s"] == 30
    # 清單上也看得到負載
    lst = (await client.get("/api/v1/scan-agents", headers=auth_headers)).json()
    rows = lst["items"] if isinstance(lst, dict) else lst
    mine = next(a for a in rows if a["id"] == str(agent.id))
    assert mine["load"]["ratio"] == 0.1
    assert mine["load"]["level"] == "ok"


async def test_load_detail_links_each_subnet_to_its_record(client, auth_headers, db_session) -> None:
    """面板上要能直接把子網路移到別的代理：每個子網路都要帶出它的 id。"""
    from app.models.section import Section
    from app.models.subnet import Subnet
    raw, agent = await _agent(db_session)
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24", scan_agent_id=agent.id)
    db_session.add(sub)
    await db_session.commit()
    await _report(client, raw, _cycle(10))
    body = (await client.get(f"/api/v1/scan-agents/{agent.id}/load", headers=auth_headers)).json()
    assert body["evaluation"]["subnets"][0]["subnet_id"] == str(sub.id)


def test_rotating_subnet_coverage_time_is_reported() -> None:
    """大子網路分段輪替：掃完一遍要幾分鐘；超過上線門檻，主機會在兩次掃描之間被判成離線。"""
    subs = [{"cidr": "198.18.0.0/18", "hosts": 4096, "total_hosts": 16382, "alive": 900, "duration_s": 40,
             "truncated": False, "chunk": 1, "rounds": 4}]
    ok = scan_load.evaluate(_cycle(40, subnets=subs), online_minutes=30)
    s = next(x for x in ok["suggestions"] if x["code"] == "rotating_large")
    assert s["params"] == {"cidr": "198.18.0.0/18", "total": 16382, "rounds": 4, "minutes": 20, "threshold": 30}
    assert ok["coverage_gap"] == []                       # 20 分鐘 < 30 分鐘門檻：不會誤判離線
    slow = scan_load.evaluate(_cycle(40, interval=600, subnets=subs), online_minutes=30)
    assert slow["coverage_gap"] == ["198.18.0.0/18"]        # 40 分鐘 > 30：兩次掃描之間會被判成離線
