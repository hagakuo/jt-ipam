"""AI 巡檢發現的分類篩選。

發現本身就帶分類標籤（對外暴露／資料衝突／疑似遺留…），畫面上看得到卻不能拿來篩，
一整頁高嚴重度的發現裡要找「所有暴露的管理介面」只能自己用眼睛掃。
"""
from __future__ import annotations

import uuid

import pytest
from app.models.ai_finding import AIFinding
from app.services.ai_audit import CATEGORIES
from httpx import AsyncClient


@pytest.fixture
async def findings(db_session):
    tag = uuid.uuid4().hex[:6]
    run_id = uuid.uuid4()
    made = []
    for cat in ("exposure", "conflict", "stale"):
        f = AIFinding(
            run_id=run_id,
            severity="high", category=cat, title=f"{cat}-{tag}",
            detail="d", recommendation="r", evidence=[], status="open",
        )
        db_session.add(f)
        made.append(f)
    await db_session.commit()
    return tag, made


@pytest.mark.anyio
async def test_filter_by_category(client: AsyncClient, auth_headers, findings):
    tag, _ = findings
    r = await client.get("/api/v1/ai-audit/findings",
                         params={"category": "exposure", "page_size": 200},
                         headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    mine = [x for x in body["items"] if x["title"].endswith(tag)]
    assert [x["title"] for x in mine] == [f"exposure-{tag}"]
    # 全部回傳的資料都必須是這個分類 —— 只檢查「我的那筆在裡面」的話，
    # 「參數被忽略、整份回傳」也會通過
    assert {x["category"] for x in body["items"]} == {"exposure"}


@pytest.mark.anyio
async def test_total_reflects_the_category_filter(client: AsyncClient, auth_headers, findings):
    """total 也要跟著縮 —— 只過濾 rows 卻回全域 count 是這個專案的老問題。"""
    all_r = await client.get("/api/v1/ai-audit/findings",
                             params={"page_size": 200}, headers=auth_headers)
    one_r = await client.get("/api/v1/ai-audit/findings",
                             params={"category": "exposure", "page_size": 200},
                             headers=auth_headers)
    assert one_r.json()["total"] < all_r.json()["total"]


@pytest.mark.anyio
async def test_unknown_category_is_ignored_not_500(client: AsyncClient, auth_headers, findings):
    """亂填分類不該讓整頁爆掉（比照 severity 的既有行為：不認得就當沒篩）。"""
    r = await client.get("/api/v1/ai-audit/findings",
                         params={"category": "no-such-thing"}, headers=auth_headers)
    assert r.status_code == 200


def test_every_category_has_a_translation():
    """下拉選單的選項是前端寫死的，漏一個分類就會出現沒有標籤的選項。"""
    import json
    import pathlib
    for loc in ("zh-TW", "en-US"):
        p = pathlib.Path(__file__).parents[2] / "frontend" / "src" / "i18n" / f"{loc}.json"
        keys = json.loads(p.read_text(encoding="utf-8"))["ai_audit"]
        missing = [c for c in CATEGORIES if f"cat_{c}" not in keys]
        assert not missing, f"{loc} 缺分類翻譯：{missing}"
