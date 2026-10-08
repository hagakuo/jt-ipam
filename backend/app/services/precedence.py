"""來源優先序的共用機制。

同一個屬性可能有好幾個來源在講話（主機名稱有 14 個、MAC 有 9 個），誰說了算由使用者
排序決定。這件事原本在五個模組裡各寫了一份 —— 主機名稱、MAC、OS、裝置名稱、型號 ——
共 661 行，形狀幾乎一樣：設定鍵、來源清單、預設順序、停用清單、60 秒快取、
排序正規化。差異只在「拿到順序之後怎麼解析」。

所以把相同的那一半收斂到這裡，五個模組只留下各自真正不同的解析邏輯。
這不只是省行數：每多一份複本，就多一個地方會忘記補上新來源（實際發生過：
新整合的 hostname 來源沒登記，`apply_observation` 會**靜靜地**把它改成 manual）。

`sources` 裡的每個名稱都必須在 `evidence.SOURCES` 登記過，否則
`tests/test_evidence_contract.py` 會擋下來 —— 那道守門要求新來源必須先回答
「你的證據會不會過期」。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.system_setting import SystemSetting

_TTL_SEC = 60.0

#: key → (載入時間, order, disabled)
_cache: dict[str, tuple[float, list[str], list[str]]] = {}


def bust_all() -> None:
    """測試用：清掉所有快取。"""
    _cache.clear()


@dataclass(frozen=True)
class Precedence:
    """一個屬性的來源優先序設定。

    `protected`：不可停用的來源（預設 manual —— 至少要留一條人工可以蓋過去的路）。
    """

    key: str
    sources: tuple[str, ...]
    default_order: tuple[str, ...]
    protected: frozenset[str] = field(default_factory=lambda: frozenset({"manual"}))

    # ── 正規化 ────────────────────────────────────────────────
    def sanitize_order(self, raw: object) -> list[str]:
        """把存下來的順序清成合法清單：去掉不認得的、補上漏掉的。

        補漏是必要的：新增來源時舊設定裡不會有它，少了這步那個來源會整個消失，
        而且是安靜地消失。
        """
        out: list[str] = []
        if isinstance(raw, list):
            for s in raw:
                if isinstance(s, str) and s in self.sources and s not in out:
                    out.append(s)
        for s in self.default_order:          # 先照預設次序補
            if s not in out:
                out.append(s)
        for s in self.sources:                # 再補預設清單也沒列到的
            if s not in out:
                out.append(s)
        return out

    def sanitize_disabled(self, raw: object) -> list[str]:
        if not isinstance(raw, list):
            return []
        return [s for s in raw
                if isinstance(s, str) and s in self.sources and s not in self.protected]

    # ── 讀寫 ──────────────────────────────────────────────────
    async def load(self, session: AsyncSession) -> tuple[list[str], list[str]]:
        now = time.monotonic()
        cached = _cache.get(self.key)
        if cached and now - cached[0] < _TTL_SEC:
            return cached[1], cached[2]
        row = await session.get(SystemSetting, self.key)
        val = row.value if row and isinstance(row.value, dict) else {}
        order = self.sanitize_order(val.get("order"))
        disabled = self.sanitize_disabled(val.get("disabled"))
        _cache[self.key] = (now, order, disabled)
        return order, disabled

    async def get_order(self, session: AsyncSession) -> list[str]:
        order, _ = await self.load(session)
        return order

    async def get_disabled(self, session: AsyncSession) -> list[str]:
        _, disabled = await self.load(session)
        return disabled

    async def save(
        self, session: AsyncSession, *, order: list[str],
        disabled: list[str] | None = None,
        updated_by_user_id: uuid.UUID | None = None,
        commit: bool = True,
    ) -> tuple[list[str], list[str]]:
        from sqlalchemy.orm.attributes import flag_modified

        clean_order = self.sanitize_order(order)
        clean_disabled = self.sanitize_disabled(disabled or [])
        row = await session.get(SystemSetting, self.key)
        if row is None:
            row = SystemSetting(key=self.key, value={}, updated_by=updated_by_user_id)
            session.add(row)
        row.value = {"order": clean_order, "disabled": clean_disabled}
        row.updated_by = updated_by_user_id
        flag_modified(row, "value")
        if commit:
            await session.commit()
        self.bust()
        return clean_order, clean_disabled

    def bust(self) -> None:
        _cache.pop(self.key, None)

    # ── 解析 ──────────────────────────────────────────────────
    def rank(self, order: list[str], source: str | None) -> int:
        """排名（越小越優先）；不在順序裡的排最後。"""
        if not source:
            return len(order) + 1
        return order.index(source) if source in order else len(order)

    def pick(
        self, candidates: dict[str, str | None], order: list[str],
        disabled: list[str] | None = None,
    ) -> tuple[str | None, str | None]:
        """依順序挑出該採用的值。回傳 (來源, 值)；都沒有回 (None, None)。"""
        off = set(disabled or [])
        for src in order:
            if src in off:
                continue
            val = candidates.get(src)
            if val is None:
                continue
            text = str(val).strip()
            if text:
                return src, text
        return None, None
