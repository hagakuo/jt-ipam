"""每個主控台 WebSocket 端點，都必須同時出現在 nginx 設定與安裝腳本裡。

這條測試守的是 0.5.155 實際發生過的事：SFTP 的 WS 端點做好了、測試也過了，但
`deploy/nginx/*.conf` 與 `scripts/jt-ipam.sh` 的 location 正規式仍只列
`(ssh|rdp|vnc|novnc|bmc)`。少了升級標頭，nginx 就把它當普通 GET 轉給後端，後端在那個
路徑上沒有 HTTP 路由 → 瀏覽器只看到一個 404，完全指不到反向代理。

本機開發時看不出來：vite 的 proxy 對所有 /api 都開 `ws: true`，正式環境才會炸。
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
NGINX_CONFS = [
    REPO / "deploy" / "nginx" / "jt-ipam.conf",
    REPO / "deploy" / "nginx" / "jt-ipam-external-proxy.conf",
]
INSTALLER = REPO / "scripts" / "jt-ipam.sh"

# /api/v1/addresses/{address_id}/<proto>/ws
_ROUTE_RE = re.compile(r"/addresses/\{[^}]+\}/([a-z0-9_]+)/ws$")


def _ws_protocols_in_app() -> set[str]:
    from starlette.routing import WebSocketRoute

    from app.main import app
    out = set()
    for r in app.routes:
        if isinstance(r, WebSocketRoute) or r.__class__.__name__ == "APIWebSocketRoute":
            m = _ROUTE_RE.search(getattr(r, "path", ""))
            if m:
                out.add(m.group(1))
    return out


def _protocols_in_text(text: str) -> set[str]:
    """抓設定/腳本裡 location 正規式列出的協定。"""
    out: set[str] = set()
    for m in re.finditer(r"addresses/\[0-9a-fA-F-\]\+/\(([a-z0-9|_]+)\)/ws", text):
        out |= set(m.group(1).split("|"))
    # 安裝腳本把清單抽成一個變數
    for m in re.finditer(r"WS_PROTOCOLS='([a-z0-9|_]+)'", text):
        out |= set(m.group(1).split("|"))
    return out


def test_the_app_actually_has_console_websockets() -> None:
    """先確認這條測試沒有因為抓不到路由而空過 —— 空集合恆等於通過。"""
    assert _ws_protocols_in_app(), "找不到任何 /<proto>/ws 路由，比對規則可能已失效"


@pytest.mark.parametrize("conf", NGINX_CONFS, ids=lambda p: p.name)
def test_every_ws_route_is_covered_by_nginx(conf: Path) -> None:
    missing = _ws_protocols_in_app() - _protocols_in_text(conf.read_text(encoding="utf-8"))
    assert not missing, (
        f"{conf.name} 的 WebSocket location 沒有涵蓋：{sorted(missing)} —— "
        "少了升級標頭，這些主控台在正式環境會連不上（後端只會看到一個普通 GET）"
    )


def test_every_ws_route_is_covered_by_the_installer() -> None:
    """升級既有站台時，安裝腳本要把 location 補寬到同一份清單。"""
    missing = _ws_protocols_in_app() - _protocols_in_text(INSTALLER.read_text(encoding="utf-8"))
    assert not missing, (
        f"scripts/jt-ipam.sh 的 WS_PROTOCOLS 沒有涵蓋：{sorted(missing)} —— "
        "既有站台升級後這些主控台會連不上"
    )
