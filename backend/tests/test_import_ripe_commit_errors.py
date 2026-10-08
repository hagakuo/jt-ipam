"""RIPE／TWNIC 匯入的單筆錯誤（CodeQL #14，2026-10-01）。

舊的 `/import/ripe/commit` 自己複製了一份寫入迴圈，把例外原文整段回給前端 —— SQLAlchemy 的錯誤
帶著 `[SQL: …]` 與 `[parameters: …]`。其他三條匯入路徑早就改走 `_apply_plans`（只留驅動那一行），
這一條漏了。另外一列失敗之後交易卡在「要先 rollback」，後面每一列跟最後的 commit 都會失敗（500）：
每一列要包一層 savepoint。
"""
from __future__ import annotations

import uuid

from app.api.v1.endpoints import import_external as imp
from app.models.section import Section
from app.models.subnet import Subnet
from sqlalchemy import select, text

SAMPLE = """\
inetnum:        192.0.2.0 - 192.0.2.255
netname:        EXAMPLE-A
descr:          first

inetnum:        198.51.100.0 - 198.51.100.255
netname:        EXAMPLE-B
descr:          second
"""


async def test_one_failed_row_does_not_leak_sql_or_sink_the_rest(client, auth_headers, db_session,
                                                                  monkeypatch) -> None:
    sec = Section(name=f"ripe-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.commit()
    real = imp.compute_master_subnet

    async def flaky(session, *, cidr, vrf_id):
        if cidr.startswith("192.0.2."):
            # 讓資料庫真的報錯：交易進入失敗狀態（沒有 savepoint 時後面全部連帶失敗）
            await session.execute(text("SELECT secret_column FROM no_such_table_for_test"))
        return await real(session, cidr=cidr, vrf_id=vrf_id)
    monkeypatch.setattr(imp, "compute_master_subnet", flaky)

    r = await client.post("/api/v1/import/ripe/commit", headers=auth_headers,
                          files={"file": ("w.txt", SAMPLE.encode(), "text/plain")},
                          data={"section_id": str(sec.id)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["inserted"] == 1
    assert len(body["errored"]) == 1
    err = body["errored"][0]["error"]
    assert "SELECT" not in err
    assert "[SQL" not in err
    cidrs = {str(c) for c in (await db_session.execute(
        select(Subnet.cidr).where(Subnet.section_id == sec.id))).scalars().all()}
    assert cidrs == {"198.51.100.0/24"}
