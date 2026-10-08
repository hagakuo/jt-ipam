"""機櫃「插入／刪除一層」與隨之而來的裝置移位。

由來：機櫃建錯（例如最下面多算了一層）時，只能一台一台把裝置往下搬，很費工。
這裡把它變成一次操作：**動一層，上面的裝置整批跟著移**。

三個刻意的決定：
1. **不刪裝置**。要刪的那一層上如果還有東西，一律擋下來並列出是哪幾台 ——
   自動刪掉別人的資料太危險，使用者要自己先搬走或刪掉。
2. **跨越該層的裝置也擋**。一台 3U 的機器橫跨要刪的那一層時，該縮短還是該整台移
   沒有唯一正解，與其猜不如問。
3. **可逆**。回應會帶一個 `undo`，照著送回來就能還原 —— 插入與刪除互為反操作，
   不需要在伺服器上存狀態。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device import Device
from app.models.location import Rack
from app.services.rack import level_heights_mm, placeable_levels, uses_rack_units


class LevelOpError(Exception):
    """這個操作不能做，附上機器可讀的代碼與參數（前端翻譯用）。"""

    def __init__(self, message: str, *, code: str, **params: Any) -> None:
        super().__init__(message)
        self.code = code
        self.params = params


@dataclass
class LevelPlan:
    """做了會發生什麼。dry-run 與實際執行走同一段程式，預覽才會與結果一致。"""

    op: str
    at: int
    rack_id: uuid.UUID
    old_height: int
    new_height: int
    moves: list[dict[str, Any]] = field(default_factory=list)
    blockers: list[dict[str, Any]] = field(default_factory=list)
    undo: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "op": self.op, "at": self.at, "rack_id": str(self.rack_id),
            "old_height": self.old_height, "new_height": self.new_height,
            "moves": self.moves, "blockers": self.blockers, "undo": self.undo,
        }


def _shifted(pos: int, op: str, at: int) -> int:
    """這台的起始層在操作後變成第幾層。"""
    if op == "remove":
        return pos - 1 if pos > at else pos
    return pos + 1 if pos >= at else pos


async def plan_level_op(
    session: AsyncSession, *, rack_id: uuid.UUID, op: str, at: int,
    height_mm: int | None = None,
) -> LevelPlan:
    """算出「動這一層」會怎麼樣。**不寫入任何東西**。"""
    if op not in ("insert", "remove"):
        raise LevelOpError("不支援的操作", code="rack_level_bad_op")
    rack = await session.get(Rack, rack_id)
    if rack is None:
        raise LevelOpError("機櫃不存在", code="rack_not_found")

    old = int(rack.u_height or 0)
    if op == "remove":
        if old <= 1:
            raise LevelOpError("只剩一層，不能再刪", code="rack_level_last_one")
        if not (1 <= at <= old):
            raise LevelOpError(f"層號超出範圍（1~{old}）", code="rack_level_out_of_range",
                               low=1, high=old)
        new = old - 1
    else:
        if old >= 99:
            raise LevelOpError("已達層數上限 99", code="rack_level_max")
        if not (1 <= at <= old + 1):
            raise LevelOpError(f"層號超出範圍（1~{old + 1})", code="rack_level_out_of_range",
                               low=1, high=old + 1)
        new = old + 1

    rows = (await session.execute(
        select(Device).where(
            Device.rack_id == rack_id,
            Device.u_position.is_not(None),
            Device.u_size.is_not(None),
        ).order_by(Device.u_position)
    )).scalars().all()

    plan = LevelPlan(op=op, at=at, rack_id=rack_id, old_height=old, new_height=new)
    for d in rows:
        pos, size = int(d.u_position or 0), int(d.u_size or 1)
        top = pos + size - 1
        if op == "remove":
            # 就在這一層上、或跨越這一層 → 擋下來，不自動刪也不自動縮
            if pos <= at <= top:
                plan.blockers.append({
                    "device_id": str(d.id), "name": d.name,
                    "u_position": pos, "u_size": size,
                    "reason": "occupies" if size == 1 else "spans",
                })
                continue
        new_pos = _shifted(pos, op, at)
        if new_pos != pos:
            if new_pos + size - 1 > placeable_levels(getattr(rack, "kind", None), new):
                plan.blockers.append({
                    "device_id": str(d.id), "name": d.name,
                    "u_position": pos, "u_size": size, "reason": "out_of_range",
                })
                continue
            plan.moves.append({
                "device_id": str(d.id), "name": d.name,
                "u_size": size, "from": pos, "to": new_pos,
            })

    # 逐層高度：刪的那層要記下來，復原時才放得回去
    heights = level_heights_mm(getattr(rack, "kind", None), rack.row_height_mm,
                               rack.level_heights, old) if not uses_rack_units(rack.kind) else []
    removed_h = int(heights[at - 1]) if (op == "remove" and heights) else None
    plan.undo = {
        "op": "insert" if op == "remove" else "remove",
        "at": at,
        "height_mm": removed_h if op == "remove" else None,
    }
    # 未使用但保留參數簽名一致（插入時呼叫端可指定新層高度）
    _ = height_mm
    return plan


async def apply_level_op(
    session: AsyncSession, *, rack_id: uuid.UUID, op: str, at: int,
    height_mm: int | None = None,
) -> LevelPlan:
    """真的做下去。有任何擋住的東西就整個不做（不做一半）。"""
    plan = await plan_level_op(session, rack_id=rack_id, op=op, at=at, height_mm=height_mm)
    if plan.blockers:
        raise LevelOpError(
            "這一層上還有裝置，請先搬走或刪掉", code="rack_level_blocked",
            count=len(plan.blockers),
            names="、".join(b["name"] for b in plan.blockers[:5]),
        )
    rack = await session.get(Rack, rack_id)
    if rack is None:
        raise LevelOpError("機櫃不存在", code="rack_not_found")

    by_id = {str(d.id): d for d in (await session.execute(
        select(Device).where(Device.rack_id == rack_id)
    )).scalars().all()}
    # 由「移動方向的遠端」開始改，避免中途撞到還沒搬的那台
    for m in sorted(plan.moves, key=lambda x: x["to"], reverse=(op == "insert")):
        dev = by_id.get(m["device_id"])
        if dev is not None:
            dev.u_position = m["to"]

    if not uses_rack_units(getattr(rack, "kind", None)):
        heights = [int(h) for h in level_heights_mm(
            getattr(rack, "kind", None), rack.row_height_mm,
            rack.level_heights, plan.old_height)]
        if op == "remove":
            del heights[at - 1]
        else:
            fill = height_mm or (heights[at - 2] if at >= 2 and heights
                                 else (heights[0] if heights else None))
            heights.insert(at - 1, int(fill or rack.row_height_mm or 300))
        rack.level_heights = heights
    rack.u_height = plan.new_height
    # 明確 flush：不要依賴 autoflush（正式環境是關的），否則呼叫端一 refresh
    # 就把還沒送出的變更丟掉，行為會隨設定而異。
    await session.flush()
    return plan
