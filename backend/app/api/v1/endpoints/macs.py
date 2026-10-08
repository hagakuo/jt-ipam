"""MAC 歷程端點：以一個 MAC 為中心查它用過的 IP、交換器埠、DHCP、裝置與時間軸（2026-10-01）。

任何登入帳號都可以查，內容依可見範圍縮放（見 services/mac_history）。
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser
from app.core.db import get_session

router = APIRouter(prefix="/macs", tags=["macs"])


@router.get("/{mac}/history")
async def mac_history_endpoint(
    mac: str,
    user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """一個 MAC 的完整歷程：用過的 IP（起訖時間、依據）、異動時間軸、交換器埠、DHCP 固定分配、
    裝置連接埠、虛擬機網卡，以及隨機 MAC 輪替時「可能是同一台」的其他 MAC。"""
    from app.core.ui_error import ui_detail
    from app.services.mac_history import mac_history
    try:
        return await mac_history(session, user=user, mac=mac)
    except ValueError as exc:
        raise HTTPException(422, detail=ui_detail("mac_invalid", "不是有效的 MAC 位址", mac=mac[:64])) from exc
