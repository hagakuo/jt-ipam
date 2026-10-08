"""OUI vendor 管理 endpoint。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.db import get_session
from app.core.ui_error import UiError, detail_of
from app.services.oui import refresh_oui_db, search_oui_vendors, vendor_for_mac
from app.services.oui import stats as oui_stats

router = APIRouter(prefix="/oui", tags=["oui"])


@router.get("/stats")
async def get_stats(
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    return await oui_stats(session)


@router.post("/refresh", dependencies=[Depends(require_admin)])
async def refresh(
    user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    from datetime import UTC, datetime

    from app.services.background_tasks import record_finished_task
    started = datetime.now(UTC)
    try:
        result = await refresh_oui_db(session)
    except Exception as exc:
        # 作業頁也要看得到失敗的那次（誰按的、為什麼），錯誤照原樣回給畫面
        await session.rollback()
        await record_finished_task(session, kind="oui.refresh", ok=False, actor_user_id=user.id,
                                   started_at=started, error=f"{type(exc).__name__}: {exc}"[:500])
        raise
    await record_finished_task(session, kind="oui.refresh", ok=True, actor_user_id=user.id,
                               started_at=started, summary=result)
    return result


@router.get("/lookup")
async def lookup(
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    mac: Annotated[str, Query(min_length=6, max_length=64)],
) -> dict[str, str | None]:
    return {"mac": mac, "vendor": await vendor_for_mac(session, mac)}


@router.get("/search")
async def search(
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    prefix: Annotated[str, Query(max_length=32)] = "",
    name: Annotated[str, Query(max_length=128)] = "",
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> dict[str, Any]:
    """依 OUI 首碼（如 22 / 00:11）或廠商名搜尋多筆 OUI 紀錄。"""
    try:
        return await search_oui_vendors(
            session, prefix=prefix or None, name=name or None, limit=limit,
        )
    except (ValueError, UiError) as exc:      # 服務層丟的是 UiError：以前沒接住，變成 500
        raise HTTPException(status_code=400, detail=detail_of(exc, "oui_bad_input")) from exc
