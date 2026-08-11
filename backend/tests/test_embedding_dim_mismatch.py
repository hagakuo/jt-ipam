"""嵌入維度不合時要說出來，不要安靜地什麼都沒索引。

實機發現：prod 設的嵌入模型回 4096 維，資料庫欄位是 vector(768) —— 每次寫入都丟
例外、被 `except (AIError, AINotConfigured): return False` 吞掉，於是三張表的
embedding 全部是 0 筆，語意搜尋從上線起就沒有真的運作過。而 reindex 回的是
`{"subnets": 0, "ip_addresses": 0, "devices": 0}`，看起來跟「沒有東西要索引」
一模一樣。

「沒做」和「做了但全失敗」在畫面上必須長得不一樣。
"""
from __future__ import annotations

import pytest
from app.services import ai as ai_mod


@pytest.mark.anyio
async def test_reindex_reports_failures_not_just_successes(db_session, monkeypatch):
    from app.models.section import Section
    from app.models.subnet import Subnet

    sec = Section(name="embed-probe-section")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24", description="測試用網段")
    db_session.add(sub)
    await db_session.flush()

    async def _boom(session, text_in):
        raise ai_mod.AIError("Embedding dim mismatch: got 4096, expected 768")

    monkeypatch.setattr(ai_mod, "embed", _boom)
    stats = await ai_mod.reindex_all(db_session)

    assert stats["subnets"] == 0
    assert stats["failed"] >= 1                  # 失敗筆數要看得到
    assert "dim mismatch" in (stats.get("error") or "")   # 而且要說出原因


@pytest.mark.anyio
async def test_reindex_with_nothing_to_do_is_not_reported_as_failure(db_session):
    """反過來：真的沒東西要索引時，不可以謊報失敗。"""
    from sqlalchemy import text as _text
    for t in ("subnets", "ip_addresses", "devices"):
        await db_session.execute(_text(f"UPDATE {t} SET description = NULL"))
    stats = await ai_mod.reindex_all(db_session)
    assert stats["failed"] == 0 and not stats.get("error")


@pytest.mark.anyio
async def test_embedding_probe_reports_the_actual_dimension(db_session, monkeypatch):
    """設定頁要能一眼看出「這個模型的維度和資料庫對不上」。

    否則使用者只會看到語意搜尋永遠沒有結果，完全猜不到是維度問題。
    """
    async def _wrong_dim(session, text_in):
        raise ai_mod.AIError("Embedding dim mismatch: got 4096, expected 768")

    monkeypatch.setattr(ai_mod, "embed", _wrong_dim)
    res = await ai_mod.probe_embedding(db_session)
    assert res["ok"] is False
    assert res["expected"] == 768
    assert "4096" in str(res.get("error"))

    async def _ok(session, text_in):
        return [0.0] * 768

    monkeypatch.setattr(ai_mod, "embed", _ok)
    res = await ai_mod.probe_embedding(db_session)
    assert res["ok"] is True and res["dim"] == 768
