"""AI 判讀可以獨立指定模型（2026-09-30 使用者要求：「ai 判讀 也要可以獨立設用什麼模型」）。

「AI 判讀」是三個按需觸發、單次提示詞的功能：
- 未授權 IP 的「AI 判讀」（/anomalies/triage）
- IP 調查的「請 AI 判讀」（/investigate?narrative=true 與串流版）
- 防火牆規則異動的「AI 解讀」（/anomalies/fw-rule-changes/{id}/analyze）

以前三個都寫死用對話模型。對話要快（互動、會叫工具），判讀要準（一次讀完一大包證據再下結論）
—— 適合的模型不一定同一個。比照 AI 巡檢：留空＝沿用對話模型與它的上下文長度，
既有安裝升上來行為不變。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import ai as ai_mod
from app.services.system_config import get_llm_config, set_llm_config


class _Resp:
    status_code = 200
    text = ""

    @staticmethod
    def json() -> dict[str, Any]:
        return {"message": {"content": "判讀內容"}}


@pytest.fixture
def sent(monkeypatch) -> list[dict[str, Any]]:
    """攔下送給 LLM 的請求主體（非串流與串流兩條路）。"""
    bodies: list[dict[str, Any]] = []

    async def _fake_request(method, url, **kw):
        bodies.append(kw["json"])
        return _Resp()

    async def _fake_stream(url, body, wait, on_chunk, headers=None, provider="ollama"):
        bodies.append(body)
        await on_chunk("判讀內容", "content")
        return "判讀內容"

    monkeypatch.setattr(ai_mod, "safe_request", _fake_request)
    monkeypatch.setattr(ai_mod, "_raw_chat_streamed", _fake_stream)
    return bodies


async def _llm(db, **kw) -> None:
    await set_llm_config(db, enabled=True, url="http://ollama.invalid:11434",
                         chat_model="chat-model:8b", num_ctx=8192, **kw)
    await db.commit()


async def _address(db) -> IPAddress:
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sn = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sn)
    await db.flush()
    ipa = IPAddress(subnet_id=sn.id, ip="198.51.100.88", hostname="judge-me", state="used")
    db.add(ipa)
    await db.commit()
    return ipa


# ── 設定本身 ──────────────────────────────────────────────────────────

async def test_setting_round_trip_and_clear(db_session) -> None:
    await _llm(db_session, ai_interpret_model=" judge-model:32b ", ai_interpret_num_ctx=32768)
    cfg = await get_llm_config(db_session)
    assert (cfg.ai_interpret_model, cfg.ai_interpret_num_ctx) == ("judge-model:32b", 32768)
    # 空字串／0 ＝清掉，回去沿用對話模型（不是存一個空模型名）
    await set_llm_config(db_session, ai_interpret_model="", ai_interpret_num_ctx=0)
    await db_session.commit()
    cfg = await get_llm_config(db_session)
    assert (cfg.ai_interpret_model, cfg.ai_interpret_num_ctx) == (None, None)
    # 跟巡檢是兩個獨立的設定
    assert cfg.ai_audit_model is None


async def test_api_exposes_and_patches_the_setting(client, auth_headers, db_session) -> None:
    await _llm(db_session)
    r = await client.patch("/api/v1/system/llm", headers=auth_headers,
                           json={"ai_interpret_model": "judge-model:32b", "ai_interpret_num_ctx": 16384})
    assert r.status_code == 200, r.text
    assert (r.json()["ai_interpret_model"], r.json()["ai_interpret_num_ctx"]) == ("judge-model:32b", 16384)
    r = await client.get("/api/v1/system/llm", headers=auth_headers)
    assert r.json()["ai_interpret_model"] == "judge-model:32b"
    r = await client.patch("/api/v1/system/llm", headers=auth_headers,
                           json={"ai_interpret_model": "", "ai_interpret_num_ctx": 0})
    assert (r.json()["ai_interpret_model"], r.json()["ai_interpret_num_ctx"]) == (None, None)
    r = await client.patch("/api/v1/system/llm", headers=auth_headers,
                           json={"ai_interpret_num_ctx": 999999})
    assert r.status_code == 422


# ── 三個判讀功能都要用它 ──────────────────────────────────────────────

async def test_ip_triage_uses_the_interpret_model(db_session, admin_user, sent) -> None:
    from app.services.ip_triage import triage_ip

    await _address(db_session)
    await _llm(db_session, ai_interpret_model="judge-model:32b", ai_interpret_num_ctx=32768)
    out = await triage_ip(db_session, admin_user, "198.51.100.88")
    assert sent[-1]["model"] == "judge-model:32b"
    assert sent[-1]["options"]["num_ctx"] == 32768
    assert out["model"] == "judge-model:32b"          # 畫面上「由哪個模型判讀」要是真的那個


async def test_fw_change_analysis_uses_the_interpret_model(db_session, admin_user, sent) -> None:
    from app.services.fw_review import analyze_change

    await _llm(db_session, ai_interpret_model="judge-model:32b")
    snap = SimpleNamespace(
        id=uuid.uuid4(), instance_name="fw-edge", source_type="opnsense",
        taken_at=datetime.now(UTC),
        diff={"added": [{"action": "pass", "interface": "wan", "src": "any", "dst": "any",
                         "dst_port": "22", "descr": "temp"}]})
    out = await analyze_change(db_session, admin_user, snap)
    assert sent[-1]["model"] == "judge-model:32b"
    # 判讀專用上下文長度沒設 → 沿用對話模型那個
    assert sent[-1]["options"]["num_ctx"] == 8192
    assert out["model"] == "judge-model:32b"


async def test_investigate_narrative_uses_the_interpret_model(client, auth_headers, db_session,
                                                               sent) -> None:
    await _address(db_session)
    await _llm(db_session, ai_interpret_model="judge-model:32b", ai_interpret_num_ctx=16384)
    r = await client.get("/api/v1/investigate", headers=auth_headers,
                         params={"ip": "198.51.100.88", "narrative": "true"})
    assert r.status_code == 200, r.text
    assert r.json()["narrative"] == "判讀內容"
    assert r.json()["model"] == "judge-model:32b"
    assert sent[-1]["model"] == "judge-model:32b"
    assert sent[-1]["options"]["num_ctx"] == 16384


async def test_investigate_stream_uses_the_interpret_model(client, auth_headers, db_session,
                                                            sent) -> None:
    await _address(db_session)
    await _llm(db_session, ai_interpret_model="judge-model:32b")
    r = await client.post("/api/v1/investigate/narrative/stream", headers=auth_headers,
                          params={"ip": "198.51.100.88"})
    assert r.status_code == 200, r.text
    assert sent[-1]["model"] == "judge-model:32b"
    assert '"model": "judge-model:32b"' in r.text          # done 事件帶模型名


async def test_unset_falls_back_to_the_chat_model(db_session, admin_user, sent) -> None:
    """既有安裝沒設這個欄位：行為跟以前一模一樣（對話模型＋對話的上下文長度）。"""
    from app.services.ip_triage import triage_ip

    await _address(db_session)
    await _llm(db_session)
    out = await triage_ip(db_session, admin_user, "198.51.100.88")
    assert sent[-1]["model"] == "chat-model:8b"
    assert sent[-1]["options"]["num_ctx"] == 8192
    assert out["model"] == "chat-model:8b"
