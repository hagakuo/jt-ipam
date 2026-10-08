"""VNC 帳號（使用者問「有些 VNC 要求輸帳號跟密碼，guacd 有支援？」，2026-09-25）。

傳統 VNC 只有密碼；macOS 螢幕共享（ARD）、UltraVNC MS 登入、VeNCrypt 帳密要帳號加密碼。
guacd 的 VNC 有 username 參數，內建引擎（aardwolf）沒有。

- 已存帳密：VNC 的帳號可以留空（其他協定仍然必填）；以前塞的佔位值「vnc」由遷移 0154 清掉，
  否則會被當成帳號「vnc」送去認證。
- guacd 參數：有填才帶 username —— 傳統 VncAuth 不看它，但帶個假的也沒意義。
"""
from __future__ import annotations

import pytest
from app.api.v1.endpoints.vnc_console import guacd_vnc_params


def test_guacd_params_carry_the_username_only_when_given() -> None:
    p = guacd_vnc_params("127.0.0.1", 5901, "", "pw")
    assert "username" not in p
    assert p["password"] == "pw" and p["port"] == "5901"
    assert p["disable-copy"] == p["disable-paste"] == "true"
    assert guacd_vnc_params("127.0.0.1", 5901, "alice", "pw")["username"] == "alice"


@pytest.mark.asyncio
async def test_vnc_credential_may_have_no_username(client, auth_headers) -> None:
    r = await client.post("/api/v1/ssh-credentials", headers=auth_headers, json={
        "label": "vnc-no-user", "username": "", "password": "pw",
        "auth_type": "password", "protocol": "vnc"})
    assert r.status_code == 201, r.text
    assert r.json()["username"] == ""

    r = await client.post("/api/v1/ssh-credentials", headers=auth_headers, json={
        "label": "vnc-with-user", "username": " alice ", "password": "pw",
        "auth_type": "password", "protocol": "vnc"})
    assert r.status_code == 201, r.text
    assert r.json()["username"] == "alice"


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["ssh", "rdp"])
async def test_other_protocols_still_need_a_username(client, auth_headers, protocol) -> None:
    r = await client.post("/api/v1/ssh-credentials", headers=auth_headers, json={
        "label": f"{protocol}-no-user", "username": "  ", "password": "pw",
        "auth_type": "password", "protocol": protocol})
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["code"] == "cred_username_required"
