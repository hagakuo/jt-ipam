"""走訪 app 的完整路由樹（給守門測試用）。

FastAPI 0.141 起，`include_router()` **不再把子路由攤平進 `app.routes`**，而是留下一個
`_IncludedRouter` 節點，實際路徑要把 include 當下的 prefix 疊回去才算得出來。
於是所有寫成 `for r in app.routes: if r.path == "/api/v1/…"` 的測試，在新版上會
**一條路由都找不到**。

這對守門測試特別危險：「找不到路由」與「沒有東西要檢查」在程式上長得一樣，
少了非空斷言就會安靜地全部通過 —— 這裡的每一條都是 RBAC／反向代理的守門，
安靜通過等於守門消失。所以走訪集中在這裡一份，並且一律搭配非空斷言使用。
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def iter_routes(app: Any) -> Iterator[tuple[str, Any]]:
    """回傳 (完整路徑, route)，遞迴穿過 include 出來的子路由。

    舊版 FastAPI 直接攤平，新版留節點；兩種形狀這裡都吃得下，所以升級或降級
    FastAPI 都不必再動測試。
    """

    def walk(routes: list[Any], prefix: str) -> Iterator[tuple[str, Any]]:
        for route in routes:
            sub = getattr(route, "original_router", None)
            if sub is not None:  # FastAPI >= 0.141 的 _IncludedRouter
                ctx_prefix = getattr(getattr(route, "include_context", None), "prefix", "") or ""
                yield from walk(sub.routes, prefix + ctx_prefix)
            else:
                yield prefix + (getattr(route, "path", "") or ""), route

    yield from walk(list(app.routes), "")
