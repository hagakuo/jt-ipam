"""Wazuh SCA（資安組態評估）摘要。

為什麼是 SCA 而不是 CVE：Wazuh 4.8 起 manager API 已經沒有任何漏洞端點（實機 4.14.5 的
150 條路徑逐條查過），唯一來源是 Wazuh Indexer —— 接上去要一組能讀取**整個 SIEM 事件**
的憑證，為了兩個數字開這條路，代價與收益不成比例。

SCA 用現有的 API 帳號就讀得到，而且「這台機器的組態有多少項不符基準」本來就比單一
CVE 數字更貼近「資安體質」。
"""
from __future__ import annotations

import uuid

import pytest
from app.models.wazuh import WazuhAgent, WazuhInstance
from app.services import wazuh as wz
from sqlalchemy import select

POLICIES = {
    "002": [
        {"name": "CIS Ubuntu Linux 20.04 LTS Benchmark v2.0.0", "score": 44,
         "pass": 86, "fail": 108},
        {"name": "Zimbra 安全組態基準 v2.0", "score": 25, "pass": 1, "fail": 3},
    ],
    "008": [],                       # SCA 沒跑過
}


async def _inst(db_session):
    inst = WazuhInstance(name=f"wz-{uuid.uuid4().hex[:6]}", api_url="https://mgr",
                         api_user="u", api_password_enc=b"x", api_password_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    for aid in POLICIES:
        db_session.add(WazuhAgent(instance_id=inst.id, agent_id=aid, status="active"))
    await db_session.flush()
    return inst


@pytest.mark.anyio
async def test_worst_policy_is_kept(db_session, monkeypatch):
    """一台機器跑多個基準時要留**分數最低**的 —— 挑最好看的等於自我安慰。"""
    inst = await _inst(db_session)

    async def fake(_inst, agent_id):
        return POLICIES[agent_id]
    monkeypatch.setattr(wz, "fetch_sca", fake)

    n = await wz.sync_sca(db_session, inst)
    await db_session.flush()
    assert n == 1                     # 008 沒有 SCA 結果 → 不算
    a = (await db_session.execute(select(WazuhAgent).where(
        WazuhAgent.instance_id == inst.id, WazuhAgent.agent_id == "002"))).scalars().first()
    assert a.sca_score == 25
    assert a.sca_policy.startswith("Zimbra")
    assert (a.sca_pass, a.sca_fail) == (1, 3)
    assert a.sca_policy_count == 2, "要記得這台其實有幾個基準，只顯示一個會誤導"


@pytest.mark.anyio
async def test_agent_without_sca_stays_empty(db_session, monkeypatch):
    """沒跑過 SCA 的 agent 欄位維持空白 —— 不可以填 0 分，那看起來像「爛到 0 分」。"""
    inst = await _inst(db_session)

    async def fake(_inst, agent_id):
        return POLICIES[agent_id]
    monkeypatch.setattr(wz, "fetch_sca", fake)

    await wz.sync_sca(db_session, inst)
    await db_session.flush()
    a = (await db_session.execute(select(WazuhAgent).where(
        WazuhAgent.instance_id == inst.id, WazuhAgent.agent_id == "008"))).scalars().first()
    assert a.sca_score is None
    assert a.sca_scanned_at is None


@pytest.mark.anyio
async def test_one_agent_failing_does_not_stop_the_rest(db_session, monkeypatch):
    inst = await _inst(db_session)

    async def fake(_inst, agent_id):
        if agent_id == "008":
            raise wz.WazuhError("boom")
        return POLICIES[agent_id]
    monkeypatch.setattr(wz, "fetch_sca", fake)

    assert await wz.sync_sca(db_session, inst) == 1


def test_no_indexer_credentials_anywhere():
    """確認 Indexer 那條路真的收乾淨了 —— 留著半套是這個專案踩過的坑。

    只檢查「有沒有實際去連 Indexer 的程式」，不禁止說明文字：檔頭那段解釋
    「為什麼不接 Indexer」要留著，否則下一個人會再接一次。
    """
    import inspect
    src = inspect.getsource(wz)
    for marker in ("indexer_url", "indexer_user", "indexer_password",
                   "wazuh-states-vulnerabilities", ":9200"):
        assert marker not in src, f"還有 Indexer 的殘留程式碼：{marker}"
