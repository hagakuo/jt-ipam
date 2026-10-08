"""API 使用手冊（docs/api.html）要涵蓋每一個 API 資源群組（2026-09-30 盤點後加的守門）。

盤點時發現 ocs、esxi、kea-dhcp、isc-dhcp、identify、event-rules、jump-hosts、ai-audit、investigate
這些群組在手冊裡一個字都沒有 —— 功能加得很快，手冊沒跟上，而外部整合的人只看手冊。
這裡只守「群組層級」：每個 `/api/v1/<群組>` 至少在手冊裡以程式碼格式出現一次（三種語言都有）。
刻意不寫的放在 _UNDOCUMENTED，而且要寫理由。
"""
from __future__ import annotations

import re
from pathlib import Path

DOC = Path(__file__).resolve().parents[2] / "docs" / "api.html"

#: 刻意不寫進手冊的群組 → 理由
_UNDOCUMENTED = {
    "client": "前端遙測（頁面載入診斷），不是給外部程式用的",
}


def _groups() -> set[str]:
    from app.main import app
    paths = app.openapi()["paths"]
    return {p.split("/")[3] for p in paths if p.startswith("/api/v1/") and len(p.split("/")) > 3}


def test_every_api_group_is_in_the_manual() -> None:
    html = DOC.read_text(encoding="utf-8")
    groups = _groups()
    assert len(groups) > 60
    def mentioned(g: str) -> bool:
        return bool(re.search(r"<code>[^<]*/(?:api/v1/)?" + re.escape(g) + r"(?![a-z0-9-])", html))
    missing = sorted(g for g in groups - set(_UNDOCUMENTED) if not mentioned(g))
    assert missing == [], ("這些 API 群組在 docs/api.html 裡找不到（至少要在 §10 資源索引列出，"
                           "刻意不寫就加進 _UNDOCUMENTED 並寫理由）：" + ", ".join(missing))


def test_the_undocumented_list_does_not_rot() -> None:
    """允許清單裡的群組要真的存在 —— 拿掉的功能不該留在例外清單裡。"""
    assert set(_UNDOCUMENTED) <= _groups()


def test_documented_api_paths_exist() -> None:
    """反方向：手冊寫的 /api/v1/… 路徑要真的有（盤點時手冊叫人打不存在的 /api/v1/me）。"""
    from app.main import app
    html = DOC.read_text(encoding="utf-8")
    from starlette.routing import WebSocketRoute

    from tests.route_walk import iter_routes
    real = list(app.openapi()["paths"])
    # WebSocket 端點不在 OpenAPI 裡（主控台、掃描代理的中繼）：從路由表補進來，手冊寫到時才比對得到
    ws = [path for path, r in iter_routes(app) if isinstance(r, WebSocketRoute)]
    assert ws, "路由表裡找不到任何 WebSocket 路由：走訪方式壞了（見 tests/route_walk.py）"
    real += ws
    # 路徑參數 {x} 視為任意一段
    pats = [re.compile("^" + re.sub(r"\\{[^/]+\\}", "[^/]+", re.escape(p)) + "/?$") for p in real]
    extra = {"/api/v1/racks/{id}/embed.svg"}          # 刻意不在 OpenAPI 的公開路由（見手冊）
    bad = []
    for m in set(re.findall(r"/api/v1/[A-Za-z0-9_./{}-]+", html)):
        path = m.rstrip(".")
        norm = re.sub(r"\{[^}]+\}", "x", path)
        if any(p.match(norm) or p.match(path) for p in pats) or path in extra:
            continue
        # 以斜線結尾＝明確寫的是前綴（例如 /api/v1/lookup/）
        if path.endswith("/") and any(r.startswith(path) for r in real):
            continue
        bad.append(path)
    assert sorted(bad) == [], "手冊寫了不存在的路徑：" + ", ".join(sorted(bad))
