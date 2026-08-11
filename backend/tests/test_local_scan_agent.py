"""掃描一律走代理：沒有指派代理的子網路，不會被任何代理撿走。

背景（客戶回報）：子網路的「掃描代理」留白時，畫面寫的是「本機直接掃（jt-ipam 主機）」，
但後端**沒有任何排程**會執行本機掃描 —— 唯一的入口是一支手動 API，前端連呼叫都沒有。
於是客戶開了掃描、等著看上線狀態，永遠等不到。

現在的作法：安裝時在 jt-ipam 主機上一併裝一個代理並標 `is_local`，migration 把既有
「已啟用掃描但未指派」的子網路接到它上面，UI 也把留白講成「不指派 —— 不會掃描」。
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select


async def _subnet(db_session, *, agent_id=None, scan_enabled=True):
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24",
                 scan_enabled=scan_enabled, scan_agent_id=agent_id)
    db_session.add(sub)
    await db_session.flush()
    return sub


async def _agent(db_session, *, is_local: bool):
    from app.models.scan_agent import ScanAgent
    a = ScanAgent(name=f"agent-{uuid.uuid4().hex[:6]}", enabled=True, is_local=is_local,
                  enroll_key_hash=uuid.uuid4().hex)
    db_session.add(a)
    await db_session.flush()
    return a


@pytest.mark.anyio
async def test_an_unassigned_subnet_belongs_to_no_agent(db_session):
    """未指派的子網路不屬於任何代理 —— 也就是不會被掃。這正是客戶踩到的狀況。"""
    from app.models.subnet import Subnet
    agent = await _agent(db_session, is_local=True)
    orphan = await _subnet(db_session, agent_id=None)
    await db_session.commit()

    mine = (await db_session.execute(
        select(Subnet.id).where(Subnet.scan_agent_id == agent.id)
    )).scalars().all()
    assert orphan.id not in mine


@pytest.mark.anyio
async def test_a_subnet_assigned_to_the_local_agent_is_picked_up(db_session):
    from app.models.subnet import Subnet
    agent = await _agent(db_session, is_local=True)
    sub = await _subnet(db_session, agent_id=agent.id)
    await db_session.commit()

    mine = (await db_session.execute(
        select(Subnet.id).where(Subnet.scan_agent_id == agent.id)
    )).scalars().all()
    assert sub.id in mine


@pytest.mark.anyio
async def test_only_one_agent_is_flagged_local(db_session):
    """`is_local` 是「跑在 jt-ipam 主機上那一個」，UI 靠它判斷本機有沒有裝。

    一般代理不該被標成 local —— 標錯會讓畫面說「本機已有代理」而其實沒有。
    """
    from app.models.scan_agent import ScanAgent
    await _agent(db_session, is_local=True)
    await _agent(db_session, is_local=False)
    await db_session.commit()

    locals_ = (await db_session.execute(
        select(ScanAgent).where(ScanAgent.is_local.is_(True))
    )).scalars().all()
    assert len(locals_) == 1


@pytest.mark.anyio
async def test_the_api_reports_is_local_so_the_ui_can_warn(client, db_session):
    """`/scan-agents` 要把 is_local 帶出來，否則前端無從分辨本機那一個。"""
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth import issue_access_token
    u = User(username=f"a-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex[:6]}@e.test",
             password_hash=hash_password("Xx!12345678xX"), is_admin=True, is_active=True)
    db_session.add(u)
    await _agent(db_session, is_local=True)
    await db_session.commit()

    r = await client.get("/api/v1/scan-agents",
                         headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(a["is_local"] for a in items), "API 沒有回報哪一個是本機代理"
