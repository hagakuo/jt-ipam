"""aardwolf 裝不起來時要講清楚原因與出路（GitHub issue #39）。

aardwolf 0.2.13 只有 CPython 3.9–3.13 的預編譯 wheel；Ubuntu 26.04 是 Python 3.14，安裝時
（刻意只收 wheel、不現場編 Rust）就會跳過。那是設計好的行為，但以前只說「缺 aardwolf」：
使用者不知道為什麼缺、也不知道 RDP 其實還能改用 FreeRDP 引擎 —— 而 VNC 主控台沒有替代引擎。
"""
from __future__ import annotations

import sys


def _py() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def test_missing_aardwolf_points_to_the_freerdp_engine() -> None:
    from app.api.v1.endpoints.rdp_console import rdp_unavailable_detail
    d = rdp_unavailable_detail("aardwolf", "aardwolf")
    assert d["code"] == "console_rdp_no_aardwolf"
    assert d["params"]["python"] == _py(), "要講出這台的 Python 版本（沒有 wheel 的原因）"
    assert "FreeRDP" in d["message"]


def test_missing_freerdp_packages_point_to_the_upgrade_script() -> None:
    from app.api.v1.endpoints.rdp_console import rdp_unavailable_detail
    d = rdp_unavailable_detail("freerdp", "xfreerdp、Xvfb")
    assert d["code"] == "console_rdp_freerdp_missing"
    assert d["params"]["missing"] == "xfreerdp、Xvfb"
    assert "jt-ipam.sh upgrade" in d["message"]


def test_vnc_says_why_and_that_there_is_no_other_engine() -> None:
    from app.api.v1.endpoints.vnc_console import vnc_unavailable_detail
    d = vnc_unavailable_detail()
    assert d["code"] == "console_vnc_not_installed"
    assert d["params"]["python"] == _py()


async def test_settings_page_knows_whether_aardwolf_is_there(client, auth_headers) -> None:
    r = await client.get("/api/v1/system/console-security", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    from app.api.v1.endpoints.rdp_console import RDP_AVAILABLE
    assert body["aardwolf_available"] is RDP_AVAILABLE
    assert body["python_version"] == _py()


def test_installer_explains_the_python_version_and_the_way_out() -> None:
    """aardwolf 裝不起來時安裝程式要講清楚（issue #39）。2026-09-27 起它只是選用的備用引擎
    （issue #42），RDP／VNC 走必裝的 guacd —— 訊息要說它是選用的、沒有東西受影響，不可以再叫人去換引擎。"""
    from pathlib import Path
    sh = (Path(__file__).resolve().parents[2] / "scripts" / "jt-ipam.sh").read_text(encoding="utf-8")
    block = sh[sh.index("install_rdp_optional() {"):sh.index("FREERDP_APT_PACKAGES=")]
    assert "3.9" in block and "3.13" in block, "要說 aardwolf 只有哪些 Python 版本的 wheel"
    assert "optional" in block, "要說 aardwolf 是選用的"
    assert "guacd" in block, "要說 RDP／VNC 走 guacd"
    assert "has no other engine" not in block, "VNC 已經有 guacd，不可以再說沒有替代引擎"
