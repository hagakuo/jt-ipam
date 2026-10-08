"""RDP 主控台的引擎可以切換（aardwolf / FreeRDP）。

為什麼要有這個開關：aardwolf（asyauth 0.0.23）在 NTLM 認證時不送 MIC —— 伺服器的
CHALLENGE 帶了 `MsvAvTimestamp` 時，MS-NLMP 要求用戶端回 MIC，而 FreeRDP 的伺服器端
（gnome-remote-desktop 用的就是它）會強制檢查。結果是同一台主機、同一組帳密，
FreeRDP 連得上、我們連不上（2026-09-17 對 Ubuntu 24 + gnome-remote-desktop 實測）。

預設曾經是 aardwolf；2026-09-27 起 RDP 與 VNC 的預設改成 guacd（使用者指示，見
test_console_engine_default.py —— guacd 沒在跑時實際連線退回內建引擎）。
"""

from __future__ import annotations

from app.services.system_config import (
    RDP_ENGINES,
    get_rdp_engine,
    set_rdp_engine,
)


async def test_default_is_guacd(db_session):
    assert await get_rdp_engine(db_session) == "guacd"


async def test_all_engines_are_offered(db_session):
    assert set(RDP_ENGINES) == {"aardwolf", "freerdp", "guacd"}


async def test_vnc_defaults_to_guacd_ssh_to_builtin_and_both_can_switch(db_session):
    """VNC 預設 guacd（2026-09-27）；SSH 預設仍是內建。"""
    from app.services.system_config import (
        get_rdp_engine,
        get_ssh_engine,
        get_vnc_engine,
        set_ssh_engine,
        set_vnc_engine,
    )
    assert await get_vnc_engine(db_session) == "guacd"
    assert await get_ssh_engine(db_session) == "builtin"
    await set_rdp_engine(db_session, engine="freerdp")
    assert await set_vnc_engine(db_session, engine="guacd") == "guacd"
    assert await set_ssh_engine(db_session, engine="guacd") == "guacd"
    # 同一把設定底下的其他值要留著（合併，不是整包換掉）
    assert await get_rdp_engine(db_session) == "freerdp"
    assert await get_vnc_engine(db_session) == "guacd"
    assert await get_ssh_engine(db_session) == "guacd"
    import pytest
    with pytest.raises(ValueError):
        await set_ssh_engine(db_session, engine="putty")


async def test_can_switch_and_it_sticks(db_session):
    assert await set_rdp_engine(db_session, engine="freerdp") == "freerdp"
    assert await get_rdp_engine(db_session) == "freerdp"
    assert await set_rdp_engine(db_session, engine="aardwolf") == "aardwolf"
    assert await get_rdp_engine(db_session) == "aardwolf"


async def test_unknown_engine_is_refused(db_session):
    """打錯字不能把主控台變成「沒有引擎」——那會是啟動時才炸的設定。"""
    import pytest
    with pytest.raises(ValueError):
        await set_rdp_engine(db_session, engine="guacamole")


async def test_switching_does_not_disturb_the_clipboard_setting(db_session):
    """兩個設定共用 `console_security` 這把 key，寫一個不可以把另一個清掉。"""
    from app.services.system_config import get_rdp_clipboard_paste, set_rdp_clipboard_paste

    await set_rdp_clipboard_paste(db_session, enabled=True)
    await set_rdp_engine(db_session, engine="freerdp")
    assert await get_rdp_clipboard_paste(db_session) is True, "貼上設定被引擎設定蓋掉了"
    assert await get_rdp_engine(db_session) == "freerdp"


async def test_endpoint_round_trips_both_fields(client, auth_headers):
    """兩個欄位共用一個端點，存一次要兩個都留著。"""
    r = await client.get("/api/v1/system/console-security", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["rdp_engine"] == "guacd", "預設不是 guacd"

    r = await client.put("/api/v1/system/console-security", headers=auth_headers,
                         json={"rdp_clipboard_paste": True, "rdp_engine": "freerdp"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["rdp_clipboard_paste"], body["rdp_engine"]) == (True, "freerdp")

    r = await client.get("/api/v1/system/console-security", headers=auth_headers)
    body = r.json()
    assert (body["rdp_clipboard_paste"], body["rdp_engine"]) == (True, "freerdp")


async def test_the_page_can_say_what_freerdp_is_missing(client, auth_headers):
    """設定頁要顯示「這台能不能用 FreeRDP」，不能用時要給得出安裝指令。

    選項擺在那裡、按下去才發現缺套件，比沒有這個選項更糟。
    """
    r = await client.get("/api/v1/system/console-security", headers=auth_headers)
    body = r.json()
    assert "freerdp_available" in body
    if body["freerdp_available"]:
        assert body["freerdp_missing"] == []
        assert body["freerdp_install_cmd"] == ""
    else:
        assert body["freerdp_missing"], "說不能用卻講不出缺什麼"
        assert "apt-get install" in body["freerdp_install_cmd"]


async def test_put_ignores_read_only_availability_fields(client, auth_headers):
    """可用性是伺服器算出來的事實，不是使用者能設的值 —— 送進來要被擋掉。"""
    r = await client.put("/api/v1/system/console-security", headers=auth_headers,
                         json={"rdp_clipboard_paste": False, "rdp_engine": "aardwolf",
                               "freerdp_available": True})
    assert r.status_code == 422, r.text


async def test_endpoint_refuses_an_unknown_engine(client, auth_headers):
    r = await client.put("/api/v1/system/console-security", headers=auth_headers,
                         json={"rdp_clipboard_paste": False, "rdp_engine": "guacamole"})
    assert r.status_code == 422, r.text


async def test_changing_the_engine_is_audited(client, auth_headers, db_session):
    """換引擎會改變『連得上／連不上』，要查得出是誰換的。"""
    from sqlalchemy import select

    from app.models.audit import AuditLog

    await client.put("/api/v1/system/console-security", headers=auth_headers,
                     json={"rdp_clipboard_paste": False, "rdp_engine": "freerdp"})
    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.object_type == "system"))).scalars().all()
    assert any((r.diff or {}).get("rdp_engine") == "freerdp" for r in rows), \
        "換 RDP 引擎沒有留下稽核記錄"
