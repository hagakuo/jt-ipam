"""裝置寫入時共用的檢查與連動（API 的新增／編輯、裝置匯入都走這裡）。

同一段規則寫兩份，改的時候通常只有一份被改到 —— 所以放在一起：
- 放進機櫃：U 位不可越界、不可與其他裝置（同安裝方向）重疊
- 設了主要 IP：該 IP 的 device_id 指回這台（雙向連結，IP 清單／拓樸才接得起來）
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.rack import RackPlacementError as PlacementError

__all__ = ["PlacementError", "check_placement", "link_primary_ip"]


async def check_placement(session: AsyncSession, obj: Any, *, exclude_device_id: uuid.UUID | None = None) -> None:
    """放進機櫃時的防呆；位置不完整（沒有機櫃或 U 位）就不檢查。不合法時丟 PlacementError。"""
    if obj.rack_id is None or obj.u_position is None or obj.u_size is None:
        return
    from app.services.rack import assert_placement_ok
    await assert_placement_ok(
        session, rack_id=obj.rack_id, u_position=obj.u_position, u_size=obj.u_size,
        rack_face=obj.rack_face, rack_slot=obj.rack_slot, rack_slot_span=obj.rack_slot_span,
        rack_vslot=obj.rack_vslot, rack_vslot_span=obj.rack_vslot_span,
        exclude_device_id=exclude_device_id,
    )


async def link_primary_ip(session: AsyncSession, obj: Any) -> None:
    """主要 IP 的 device_id 指回這台裝置。"""
    if not obj.primary_ip_id:
        return
    from app.models.address import IPAddress
    pip = await session.get(IPAddress, obj.primary_ip_id)
    if pip is not None and pip.device_id != obj.id:
        pip.device_id = obj.id
