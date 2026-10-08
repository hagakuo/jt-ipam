"""規則異動偵測必須看得到「這一輪剛寫進去的規則」。

由來（2026-09-04，做 MikroTik 整合時發現）：正式環境的 session 是 `autoflush=False`，
而多數整合的規則同步是**整批刪掉再整批寫回**：

    await session.execute(delete(Rule).where(...))   # 立刻進 DB
    for r in rows: session.add(Rule(...))            # 還躺在 session 裡

接著 `run_sentinel()` 用 `select(Rule)` 去讀 —— 讀到的是 **DB 的現況＝空的**。
結果是鏡像取代的廠牌（FortiGate／Palo Alto／MikroTik）每輪都存下一份**空快照**，
規則異動偵測形同沒有運作，而且畫面上完全看不出異狀（快照筆數是 0，不是錯誤）。

⚠️ 這個測試**一定要自己關掉 autoflush**：測試 fixture 預設 `autoflush=True`，
不關的話下面這一整個情境在測試裡永遠是綠的（CLAUDE.md 地雷 12）。
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import delete, select


@pytest.mark.anyio
async def test_sentinel_sees_rules_written_in_the_same_transaction(db_session: Any) -> None:
    from app.models.fw_snapshot import FwRuleSnapshot
    from app.models.mikrotik import MikroTikRouter, MikroTikRule
    from app.services.fw_review import run_sentinel

    db_session.autoflush = False        # ← 比照正式環境，不加這行等於沒測

    router = MikroTikRouter(
        name=f"sentinel-{uuid.uuid4().hex[:8]}", api_url="https://192.0.2.9",
        api_username="ipam", api_password_enc=b"x", api_password_nonce=b"y")
    db_session.add(router)
    await db_session.flush()

    # 模擬一輪「鏡像取代」：先刪（直接進 DB）、再加（留在 session）
    await db_session.execute(
        delete(MikroTikRule).where(MikroTikRule.router_id == router.id))
    for i in range(3):
        db_session.add(MikroTikRule(
            router_id=router.id, table_name="filter", position=i,
            chain="forward", action="accept", dst_address=f"10.0.0.{i}",
            protocol="tcp", dst_port="443"))

    await run_sentinel(db_session, source_type="mikrotik", instance=router)

    snap = (await db_session.execute(
        select(FwRuleSnapshot).where(FwRuleSnapshot.instance_id == router.id),
    )).scalars().first()
    assert snap is not None, "沒有存下快照"
    assert snap.rule_count == 3, (
        f"快照只看到 {snap.rule_count} 條規則 —— 沒有 flush，讀到的是刪除後的 DB 現況")
