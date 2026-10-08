"""**每一個**主控台都要問過連線出口（issue #24 階段一）。

漏掉任何一條的後果不是「連不上」而是「連到別人」：會用跳板的站台多半正是私網網段
重疊的站台，後端直連同一個私網位址，很可能打到另一個客戶的機器 —— 而畫面上一切正常。

所以這裡把「六個主控台各自怎麼處理出口」寫成清單，新增主控台時必須在這裡表態。
"""

from __future__ import annotations

from pathlib import Path

import pytest

EP = Path(__file__).resolve().parent.parent / "app" / "api" / "v1" / "endpoints"

#: 走跳板的主控台：解析出口 → 開通道 → 用通道的位址連 → finally 還回去
TUNNELLED = ("ssh_console", "sftp_console", "rdp_console", "vnc_console")

#: 刻意**不**走跳板的，各有各的理由（理由要寫在程式裡，不是只在這裡）
EXCLUDED = {
    # IPMI／SOL 是 UDP 623，SSH 的本機轉發只有 TCP → 擋下來，不可默默直連
    "bmc_console": "jump_unsupported",
    # 連的是虛擬化主機（Proxmox 整合設定的 base_url），不是這筆 IP 的位址 → 出口不適用
    "novnc_console": "不適用",
}


def _src(name: str) -> str:
    return (EP / f"{name}.py").read_text(encoding="utf-8")


@pytest.mark.parametrize("name", TUNNELLED)
def test_console_resolves_and_uses_the_route(name: str) -> None:
    src = _src(name)
    assert "console_route.resolve_route(s, ip)" in src, f"{name} 沒有解析連線出口"
    assert "console_route.open_route(route," in src, f"{name} 沒有開通道"
    assert "await tunnel.aclose()" in src, f"{name} 沒有在 finally 還回通道"
    assert "jump_failed" in src, f"{name} 跳板失敗時沒有回可讀的錯誤"


#: 每個主控台「真正撥出去」的那一行長什麼樣。逐條寫死是刻意的：
#: 這是最容易犯又最看不出來的錯 —— 通道開了、稽核也寫了「經由跳板」，
#: 但實際連出去的還是原本那個目標 IP。
DIAL_SITE = {
    "ssh_console": "host, port = tunnel.host, tunnel.port",
    "sftp_console": "conn = await asyncssh.connect(\n            dial_host, port=dial_port,",
    "rdp_console": "return factory.create_connection_newtarget(tunnel.host, io)",
    "vnc_console": "conn = factory.create_connection_newtarget(dial_host, io)",
}


@pytest.mark.parametrize("name", TUNNELLED)
def test_console_dials_the_tunnel_not_the_original_target(name: str) -> None:
    src = _src(name)
    assert DIAL_SITE[name] in src, f"{name} 沒有把連線目標換成通道的位址"


#: RDP 有兩個引擎（aardwolf / FreeRDP）。跳板這件事**每個引擎各做一次** ——
#: 只驗其中一個，另一個可以整條繞過通道直連目標，而畫面上一切正常。
RDP_ENGINE_DIAL_SITES = (
    "return factory.create_connection_newtarget(tunnel.host, io)",   # aardwolf
    "host=tunnel.host, port=tunnel.port, username=username",         # FreeRDP
)


#: guacd 引擎（RDP／VNC／SSH）：交給 guacd 的 hostname／port 也必須是通道的位址
GUACD_DIAL_SITES = {
    "rdp_console": '"hostname": tunnel.host, "port": str(tunnel.port),',
    "vnc_console": 'params = guacd_vnc_params(dial_host, dial_port, username, password)',
    # ssh 的 host／port 在上面已經換成通道的位址（`host, port = tunnel.host, tunnel.port`）
    "ssh_console": '"hostname": host, "port": str(port), "username": username,',
}


@pytest.mark.parametrize("name", sorted(GUACD_DIAL_SITES))
def test_guacd_engine_dials_the_tunnel(name: str) -> None:
    assert GUACD_DIAL_SITES[name] in _src(name), f"{name} 的 guacd 引擎沒有把連線目標換成通道的位址"


def test_every_rdp_engine_dials_the_tunnel() -> None:
    src = _src("rdp_console")
    for site in RDP_ENGINE_DIAL_SITES:
        assert site in src, f"有一個 RDP 引擎沒有把連線目標換成通道的位址：{site!r}"


def test_rdp_and_vnc_put_the_port_in_the_url() -> None:
    """aardwolf 的 `create_connection_newtarget()` **只換 ip/hostname、不動連接埠**。

    連接埠是 `from_url()` 解析出來的，所以 URL 裡沒帶埠的話，走跳板時會連到
    127.0.0.1 的**標準埠** —— 也就是後端主機自己，而不是通道的另一端。
    """
    rdp = _src("rdp_console")
    assert "@{tunnel.host}:{tunnel.port}/" in rdp
    vnc = _src("vnc_console")
    assert "@{dial_host}:{dial_port}/" in vnc
    assert "vnc://{dial_host}:{dial_port}/" in vnc


@pytest.mark.parametrize("name", sorted(EXCLUDED))
def test_excluded_console_refuses_or_documents_why(name: str) -> None:
    src = _src(name)
    assert EXCLUDED[name] in src, f"{name} 沒有寫下為什麼不走跳板"


def test_bmc_refuses_instead_of_silently_going_direct() -> None:
    """BMC 的目標**就是**這筆 IP 的位址，所以默默直連＝可能連到別人。要擋。"""
    src = _src("bmc_console")
    assert "console_route.resolve_route(s, ip)" in src
    assert "if not isinstance(route, console_route.Direct):" in src
    assert "UDP 623" in src, "沒有講出擋下來的原因，現場只會覺得功能壞了"


def test_no_console_lets_the_caller_choose_the_jump_host() -> None:
    """出口只能從資料庫的指派推導。

    一旦接受呼叫端指定，主控台就退化成「可以連任何地方的通用 proxy」——
    那正是每個主控台檔案開頭都特別聲明防掉的事。
    """
    for name in (*TUNNELLED, *EXCLUDED):
        src = _src(name)
        assert "cfg.get(\"jump" not in src, f"{name} 讓前端指定跳板"
        assert "jump_host_id\")" not in src, f"{name} 讓前端指定跳板"
