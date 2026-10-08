"""主控台連線失敗時，訊息要指向真正的原因。

由來（2026-09-02 實機）：使用者給了一台開著 VNC 的位址要我們連連看，畫面回
「連線/認證失敗（密碼錯誤或 VNC 設定）」。實際上密碼連送出去的機會都沒有 ——
目標在送出 RFB 版本字串之前就把 TCP 關掉了（底層錯誤是 `Stream ended!`）。
真正的原因是那個位址**同時被三台虛擬機宣稱**（ARP 有三個 MAC 回應），連線落到
沒有 VNC 的那一台。

被指去檢查密碼的人，永遠查不到這個。所以錯誤訊息要 (a) 分類、(b) 帶底層原文，
與整合頁 `core/safe_http.transport_detail` 同一個原則。
"""

from __future__ import annotations

import pytest

from app.api.v1.endpoints.vnc_console import _classify_connect_error


def test_stream_ended_is_not_reported_as_a_password_problem() -> None:
    code, msg = _classify_connect_error(Exception("Stream ended!"))
    assert code == "handshake_failed"
    assert "密碼" not in msg.split("原始錯誤")[0], "交握前就斷線，不可以把人指去查密碼"
    assert "Stream ended!" in msg, "要帶底層原文，否則使用者與我們都只能用猜的"


def test_multiple_hosts_on_one_address_is_named_as_a_possible_cause() -> None:
    """這是實機真正的原因，而且是使用者自己查得出來的（IPAM 本來就會記多個 MAC）。"""
    _, msg = _classify_connect_error(Exception("Stream ended!"))
    assert "多台主機" in msg


@pytest.mark.parametrize(
    ("err", "expected_code"),
    [
        (ConnectionRefusedError("[Errno 111] Connection refused"), "connect_failed"),
        (TimeoutError("timed out"), "connect_failed"),
        (ConnectionResetError("Connection reset by peer"), "handshake_failed"),
        (Exception("Authentication failed"), "auth_failed"),
    ],
)
def test_classification(err: BaseException, expected_code: str) -> None:
    code, msg = _classify_connect_error(err)
    assert code == expected_code
    assert str(err).split("]")[-1].strip()[:10] in msg or err.__class__.__name__ in msg


def test_detail_is_bounded() -> None:
    """訊息會顯示在畫面上（也可能進稽核）—— 不可以把一整串內部訊息倒出來。"""
    _, msg = _classify_connect_error(Exception("x" * 5000))
    assert len(msg) < 400
