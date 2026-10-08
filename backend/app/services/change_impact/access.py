"""讀取時的權限（規格 §11.1）：每次看 run、證據、AI 解說、匯出都重新檢查。

分析當下的可見範圍算成 `visible_scope_hash` 存在 run 上；之後讀取時範圍變了：
- 看不到的發現與證據直接不回（不留名稱、不留數量）
- AI 解說若是用不同範圍產生的，整份隱藏（不能只遮 id 卻留下名稱與數量）
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.change_impact.model import stable_hash

_TYPES = ("ip", "subnet", "device")


@dataclass
class Viewer:
    user: Any
    is_admin: bool
    global_read: bool
    vis: dict[str, set[uuid.UUID] | None]

    def can(self, vtype: str | None, vid: uuid.UUID | None) -> bool:
        if vtype in (None, "global"):
            return self.global_read
        if vtype == "admin":
            return self.is_admin
        v = self.vis.get(vtype)
        return v is None or (vid is not None and vid in v)

    def scope_hash(self) -> str:
        return stable_hash({"admin": self.is_admin, "global": self.global_read,
                            "vis": {k: (None if v is None else sorted(str(x) for x in v)) for k, v in self.vis.items()}})


async def viewer(session: AsyncSession, user: Any) -> Viewer:
    from app.mcp.tools import has_global_read
    from app.services.permission import visible_ids
    vis = {t: await visible_ids(session, user=user, object_type=t) for t in _TYPES}  # type: ignore[arg-type]
    return Viewer(user=user, is_admin=bool(getattr(user, "is_admin", False)),
                  global_read=await has_global_read(session, user), vis=vis)
