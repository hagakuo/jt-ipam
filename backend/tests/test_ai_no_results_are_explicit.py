"""工具查無結果時，回應必須讓模型「不可能誤讀成有資料」。

GitHub issue #34：使用者叫 AI 執行 `list_anomalies`，模型卻回了兩個根本不在這套 IPAM 裡的
位址（203.0.113.50 / 192.0.2.15，MAC 還是 VMware 的示範前綴）—— 典型的「工具沒東西可回，
小模型自己編一段像樣的出來」。

事實由確定性查詢決定、模型只負責敘述，所以要補在**工具輸出**那一端，而不是指望提示詞裡
那句「不要編造」能被一個量化過的小模型讀到。
"""
from __future__ import annotations

import pytest

from app.mcp.tools import TOOLS


@pytest.mark.anyio
async def test_list_anomalies_result_is_unambiguous(db_session, admin_user) -> None:
    out = await TOOLS["list_anomalies"]["fn"](db_session, admin_user, limit=5)
    # 有沒有東西要一眼看得出來，不能只給一疊 0
    assert out["total"] == sum(out["counts"].values())
    assert out.get("note"), "工具結果要帶一句明確的指示，別讓模型自己揣摩"
    if out["total"] == 0:
        assert "invent" in out["note"].lower(), "查無結果時要明講不准編造"


@pytest.mark.anyio
async def test_tool_error_keeps_the_underlying_message(db_session, admin_user, monkeypatch) -> None:
    """只回例外類別名稱＝把「為什麼壞了」丟掉，模型與使用者都只看到 'tool failed'。"""
    from app.mcp import tools as mcp_tools
    from app.services import ai as ai_svc

    async def boom(session, user, **kw):
        raise RuntimeError("detector exploded: column x does not exist")

    monkeypatch.setitem(mcp_tools.TOOLS["list_anomalies"], "fn", boom)
    out = await ai_svc._run_tool_calls(
        db_session, admin_user, [{"function": {"name": "list_anomalies", "arguments": {}}}])
    assert len(out) == 1
    body = out[0]["content"]
    assert "RuntimeError" in body
    assert "detector exploded" in body, "只給例外類別名稱，看不出到底怎麼了"
