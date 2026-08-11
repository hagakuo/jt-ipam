"""巡檢要看得到「這個網段到底有沒有在掃」。

實機回報：一條發現寫著「大量未經監控的 IP 位址…這可能代表存在監控盲點」，建議
「檢查監控系統是否涵蓋了該子網路的所有範圍」。查了資料才知道：**那個網段有開啟掃描、
也有指派代理，233 個位址裡 130 個掃到過** —— 掃描一直在跑，是那 103 筆從來沒有回應。

模型沒有錯：快照裡每個子網路只有 CIDR 與說明，沒有任何欄位說得出「有沒有在掃」，
它看到一堆沒有最後出現時間的位址，只能推「大概沒被監控」。建議因此指向錯的方向 ——
去查監控涵蓋，而真正該做的是清掉過期紀錄、或確認那些主機不回應探測。

**同一份資料，兩種完全不同的處置**，差別只在一個我們沒送出去的欄位。
"""
from __future__ import annotations

import uuid

import pytest
from app.services import ai_audit as aa


async def _admin(db_session):
    from app.core.security import hash_password
    from app.models.user import User
    u = User(username=f"cov-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex[:6]}@e.test",
             password_hash=hash_password("Xx!12345678xX"), is_admin=True, is_active=True)
    db_session.add(u)
    await db_session.flush()
    return u


@pytest.mark.anyio
async def test_the_snapshot_says_whether_a_subnet_is_scanned(db_session):
    from datetime import UTC, datetime

    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet

    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24", description="測試",
                 scan_enabled=True)
    db_session.add(sub)
    await db_session.flush()
    # 一筆掃到過、一筆從來沒有
    db_session.add(IPAddress(subnet_id=sub.id, ip="198.51.100.10",
                             last_seen_scanner=datetime.now(UTC)))
    db_session.add(IPAddress(subnet_id=sub.id, ip="198.51.100.11"))
    await db_session.flush()

    snap = await aa._collect(db_session, await _admin(db_session))
    row = next(s for s in snap["subnets"] if s["cidr"].startswith("198.51.100."))
    assert row["scan_enabled"] is True
    # 涵蓋率：模型要能分辨「沒在掃」與「在掃但這些位址沒回應」
    assert row["ips_seen"] == 1
    assert row["ips_total"] == 2


@pytest.mark.anyio
async def test_a_subnet_with_scanning_off_is_marked_as_such(db_session):
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="203.0.113.0/24", scan_enabled=False)
    db_session.add(sub)
    await db_session.flush()
    snap = await aa._collect(db_session, await _admin(db_session))
    row = next(s for s in snap["subnets"] if s["cidr"].startswith("203.0.113."))
    assert row["scan_enabled"] is False


def test_the_prompt_tells_the_model_to_use_coverage_before_calling_it_a_blind_spot():
    """光給欄位不夠 —— 要明講：在掃卻沒回應，跟根本沒在掃，處置完全不同。"""
    p = aa._PROMPT
    assert "scan_enabled" in p or "scanned" in p.lower()
    assert "blind spot" in p.lower() or "coverage" in p.lower()
