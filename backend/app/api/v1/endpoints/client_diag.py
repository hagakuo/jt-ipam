"""前端的頁面載入診斷：頁面是怎麼開起來的（一般開啟／重新載入／被瀏覽器回收後重載…）。

為什麼要有這個：使用者回報「從別的分頁切回來，整頁會重新載入」。伺服器只看得到請求，
分不出是瀏覽器把背景分頁回收了（`document.wasDiscarded`）、分頁被凍結、還是我們自己的
「程式檔載入失敗就重載」觸發的（2026-09-25 查了一輪 nginx 記錄仍無法定論）。
所以頁面一開就回報一筆，寫進後端日誌（grep `client page load`）。

只寫日誌、不存資料庫、不改任何資料；欄位全部限長，內容當成不可信的文字處理（去掉控制字元）。
"""

from __future__ import annotations

import logging
import re
from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import Field

from app.api.v1.dependencies import CurrentUser
from app.schemas.base import StrictModel

router = APIRouter(prefix="/client", tags=["client"])
_log = logging.getLogger("jt-ipam.client")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class PageLoadIn(StrictModel):
    path: str = Field(default="", max_length=200)
    nav_type: Literal["navigate", "reload", "back_forward", "prerender", "unknown"] = "unknown"
    was_discarded: bool = False
    prerendered: bool = False
    visibility: Literal["visible", "hidden", "prerender", "unknown"] = "unknown"
    #: 我們自己的「程式檔載入失敗就重載」留下的原因（router/index.ts 的 reloadOnce）
    reload_reason: str | None = Field(default=None, max_length=300)
    #: 上一次頁面存活期間的生命週期事件（visibility／freeze／resume／pagehide，最多 20 筆）
    lifecycle: list[str] = Field(default_factory=list, max_length=20)
    build: str | None = Field(default=None, max_length=40)


def _clean(v: object, limit: int = 300) -> str:
    return _CTRL.sub(" ", str(v))[:limit]


@router.post("/page-load", status_code=204)
async def page_load(payload: PageLoadIn, user: CurrentUser, request: Request) -> Response:
    from app.core.rate_limit import limit_per_ip
    await limit_per_ip(request, name="default")
    _log.info(
        "client page load user=%s ip=%s path=%s nav=%s discarded=%s prerendered=%s visibility=%s "
        "reload_reason=%s lifecycle=%s build=%s",
        user.username, request.client.host if request.client else "-", _clean(payload.path, 200),
        payload.nav_type, payload.was_discarded, payload.prerendered, payload.visibility,
        _clean(payload.reload_reason or "-"), _clean(" | ".join(_clean(x, 80) for x in payload.lifecycle), 1800),
        _clean(payload.build or "-", 40),
    )
    return Response(status_code=204)
