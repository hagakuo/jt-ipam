"""版本資訊頁要看得到 FreeRDP 引擎的相依。

那一頁是管理員用來確認「這台裝了什麼」的地方。RDP 引擎選了 FreeRDP 卻連不上時，
第一個該看的就是這裡 —— 缺套件的話應該一眼看出來，而不是去翻伺服器日誌。
"""

from __future__ import annotations


async def test_version_page_lists_the_freerdp_tools(client, auth_headers):
    r = await client.get("/api/v1/system/version", headers=auth_headers)
    assert r.status_code == 200, r.text
    tools = r.json()["host"]["optional_tools"]
    for exe in ("xfreerdp", "Xvfb", "ffmpeg", "xclip"):
        assert exe in tools, f"版本頁沒有列出 {exe}"
        entry = tools[exe]
        assert set(entry) >= {"present", "package", "used_by"}
        assert isinstance(entry["present"], bool)
        # 套件名是要印給人照著 apt install 的
        assert entry["package"], f"{exe} 沒有對應的套件名"
        assert "RDP" in entry["used_by"], f"{exe} 沒有說明它是給誰用的"


async def test_the_existing_tools_are_still_there(client, auth_headers):
    """補東西不可以把原本的擠掉。"""
    r = await client.get("/api/v1/system/version", headers=auth_headers)
    tools = r.json()["host"]["optional_tools"]
    for exe in ("ping", "traceroute", "tracepath"):
        assert exe in tools


async def test_tool_list_matches_what_the_engine_actually_needs(client, auth_headers):
    """列出來的與引擎真正檢查的要是同一份。

    兩份清單各自維護的話，總有一天版本頁說「都裝好了」而連線仍然失敗。
    """
    from app.services.rdp_freerdp import required_binaries

    r = await client.get("/api/v1/system/version", headers=auth_headers)
    tools = r.json()["host"]["optional_tools"]
    for exe, pkg in required_binaries().items():
        assert tools[exe]["package"] == pkg, f"{exe} 的套件名與引擎那邊不一致"


async def test_guacd_is_listed_as_required_and_aardwolf_as_optional(client, auth_headers, monkeypatch):
    """guacd 是必要元件、aardwolf 改為選用（2026-09-27，GitHub issue #42）：版本頁要列得出來、看得出有沒有在跑。"""
    async def fake_probe(*, use_cache: bool = True):
        return {"ok": False, "address": "127.0.0.1:4822", "protocols": {}, "error": "connection refused"}
    monkeypatch.setattr("app.services.guacd.probe", fake_probe)
    r = await client.get("/api/v1/system/version", headers=auth_headers)
    assert r.status_code == 200, r.text
    host = r.json()["host"]
    g = host["required_tools"]["guacd"]
    assert g["running"] is False
    assert "RDP / VNC" in g["used_by"]
    assert "aardwolf" in host["optional_tools"]
    assert "aardwolf" not in host["required_tools"]
