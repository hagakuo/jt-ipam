"""PVE 主控台的兩階段驗證（GitHub issue #23）。

PVE 對啟用 TFA 的帳號回的是 HTTP 200 + 「挑戰票證」，不是錯誤：
`{"data": {"ticket": "PVE:!tfa!…", "NeedTFA": 1}}`。
把它當成正常 ticket 收下，後面開 vncwebsocket 才會失敗，而且錯誤訊息
完全看不出真正原因 —— 那正是這個 issue 的症狀。
"""

from __future__ import annotations

import pytest
from app.services import pve_console as pc


class _Resp:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._p = payload
        self.status_code = status

    def json(self) -> dict:
        return self._p


def _patch(monkeypatch, responses: list[dict]) -> list[dict]:
    """依序回傳 responses；同時把每次送出的 body 收集起來供斷言。"""
    sent: list[dict] = []
    seq = list(responses)

    async def fake(_m, _url, *, json=None, timeout=None, verify=None):
        sent.append(json or {})
        return _Resp(seq.pop(0))

    monkeypatch.setattr(pc, "safe_request", fake)
    return sent


@pytest.mark.anyio
async def test_tfa_challenge_asks_for_code_instead_of_failing_obscurely(monkeypatch) -> None:
    """沒帶驗證碼 → 明確回 tfa_required，而不是拿挑戰票證去連線然後神祕失敗。"""
    _patch(monkeypatch, [{"data": {"ticket": "PVE:!tfa!abc", "NeedTFA": 1}}])
    with pytest.raises(pc.PveConsoleError) as exc:
        await pc.pve_login("https://pve.example.com", "root@pam", "pw", False)
    assert exc.value.code == "tfa_required"
    assert exc.value.http_status == 401


@pytest.mark.anyio
async def test_tfa_code_exchanges_for_real_ticket(monkeypatch) -> None:
    """帶了驗證碼 → 用 tfa-challenge 換到真正的 ticket。"""
    sent = _patch(monkeypatch, [
        {"data": {"ticket": "PVE:!tfa!abc", "NeedTFA": 1}},
        {"data": {"ticket": "PVE:root@pam:REAL", "CSRFPreventionToken": "csrf1"}},
    ])
    ticket, csrf = await pc.pve_login(
        "https://pve.example.com", "root@pam", "pw", False, tfa_code="123456",
    )
    assert ticket == "PVE:root@pam:REAL"
    assert csrf == "csrf1"
    # 第二次請求要帶挑戰票證與 totp: 前綴
    assert sent[1]["tfa-challenge"] == "PVE:!tfa!abc"
    assert sent[1]["password"] == "totp:123456"
    assert sent[1]["username"] == "root@pam"


@pytest.mark.anyio
async def test_wrong_tfa_code_is_reported_clearly(monkeypatch) -> None:
    """驗證碼錯誤時 PVE 仍會回挑戰票證 → 要當成失敗，不可再拿去連線。"""
    _patch(monkeypatch, [
        {"data": {"ticket": "PVE:!tfa!abc", "NeedTFA": 1}},
        {"data": {"ticket": "PVE:!tfa!abc"}},
    ])
    with pytest.raises(pc.PveConsoleError) as exc:
        await pc.pve_login(
            "https://pve.example.com", "root@pam", "pw", False, tfa_code="000000",
        )
    assert exc.value.code == "tfa_failed"


@pytest.mark.anyio
async def test_account_without_tfa_is_unaffected(monkeypatch) -> None:
    """沒開 TFA 的帳號維持單次請求，不能因為這個修改多打一次。"""
    sent = _patch(monkeypatch, [
        {"data": {"ticket": "PVE:root@pam:REAL", "CSRFPreventionToken": "csrf1"}},
    ])
    ticket, _csrf = await pc.pve_login("https://pve.example.com", "root@pam", "pw", False)
    assert ticket == "PVE:root@pam:REAL"
    assert len(sent) == 1, "沒開 TFA 卻打了兩次 /access/ticket"
