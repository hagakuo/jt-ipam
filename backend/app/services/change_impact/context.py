"""一次分析的工作區：可見範圍、來源狀態、收集到的證據／發現／缺口。

權限先算好再查：每個 adapter 只拿得到使用者看得到的東西（規格 §11.1「以發起者身分、不以系統管理員分析」）。
全域基礎設施（DNS、DHCP、防火牆、NAT、LibreNMS、虛擬化）要全域讀取；監控代理與憑證只給管理員 ——
看不到的類別不查，改記一筆 permission_limited 缺口（固定文案，不透露隱藏了多少）。
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.change_impact.model import Evidence, Finding, Gap, TargetAddr
from app.services.change_impact.scenario import Scenario
from app.services.change_impact.sources import ADMIN_CATEGORIES, GLOBAL_CATEGORIES, SourceStatus


class LimitExceeded(Exception):
    """證據或發現超過上限：結果標 partial、記下截斷在哪裡，不可以回報完整成功。"""

    def __init__(self, what: str, limit: int) -> None:
        super().__init__(f"{what} > {limit}")
        self.what, self.limit = what, limit


@dataclass
class Ctx:
    session: AsyncSession
    user: Any
    scenario: Scenario
    now: datetime
    sources: list[SourceStatus]
    is_admin: bool
    global_read: bool
    vis: dict[str, set[uuid.UUID] | None]
    limits: dict[str, Any]
    checkpoint: Callable[[str], Awaitable[None]] | None = None
    evidence: dict[str, Evidence] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    gaps: dict[str, Gap] = field(default_factory=dict)
    skipped: set[str] = field(default_factory=set)
    # 根位址是否落在別的子網路也有的位址空間（重疊網段）：整合沒設範圍時，比中的證據只能算推定
    overlap: dict[uuid.UUID, bool] = field(default_factory=dict)

    # ── 權限 ──
    def can_see(self, object_type: str, object_id: uuid.UUID | None) -> bool:
        if object_id is None:
            return False
        v = self.vis.get(object_type)
        return v is None or object_id in v

    def allowed(self, category: str) -> bool:
        """這個類別這個使用者看得到嗎？看不到就記一次 permission_limited。"""
        ok = self.is_admin if category in ADMIN_CATEGORIES else (
            self.global_read if category in GLOBAL_CATEGORIES else True)
        if not ok and category not in self.skipped:
            self.skipped.add(category)
            self.gap(category, "permission_limited", affected=category)
        return ok

    def visibility_for(self, category: str) -> tuple[str, uuid.UUID | None]:
        if category in ADMIN_CATEGORIES:
            return ("admin", None)
        return ("global", None)

    # ── 收集 ──
    def add(self, ev: Evidence) -> str:
        if ev.key not in self.evidence:
            if len(self.evidence) >= int(self.limits.get("max_evidence", 20000)):
                raise LimitExceeded("evidence", int(self.limits.get("max_evidence", 20000)))
            ev.collected_at = ev.collected_at or self.now
            self.evidence[ev.key] = ev
        return ev.key

    def find(self, f: Finding) -> None:
        if len(self.findings) >= int(self.limits.get("max_findings", 5000)):
            raise LimitExceeded("findings", int(self.limits.get("max_findings", 5000)))
        self.findings.append(f)

    def gap(self, category: str, reason: str, *, scope: str | None = None, affected: str | None = None,
            hint: str | None = None, **params: Any) -> None:
        g = Gap(category=category, reason_code=reason, params=params, source_scope=scope,
                affected_analysis=affected, remediation_hint=hint)
        self.gaps.setdefault(g.key(), g)

    async def check(self, stage: str) -> None:
        if self.checkpoint is not None:
            await self.checkpoint(stage)

    # ── 來源 ──
    def sources_of(self, category: str) -> list[SourceStatus]:
        return [s for s in self.sources if category in s.categories]

    def source(self, kind: str, sid: uuid.UUID | None) -> SourceStatus | None:
        return next((s for s in self.sources if s.kind == kind and s.id == sid), None)

    def freshness_of(self, kind: str, sid: uuid.UUID | None) -> str:
        s = self.source(kind, sid)
        return s.freshness if s else "unknown"

    def strength_for(self, src: SourceStatus | None, root: TargetAddr) -> str | None:
        """整合有設範圍且涵蓋根位址 → 規則預設；沒設範圍又有重疊網段 → 推定，並記缺口（規格 §5.1）。"""
        if self.in_scope(src, root) is None and self.overlap.get(root.ip_id):
            self.gap("scope", "scope_unset_overlap", scope=src.ref if src else None,
                     source=src.name if src else "", address=root.ip_text)
            return "inferred"
        return None

    def in_scope(self, src: SourceStatus | None, root: TargetAddr) -> bool | None:
        """整合有沒有涵蓋這個根位址的子網路：True／False；沒設範圍回 None（不確定）。"""
        if src is None or not src.scope_subnet_ids:
            return None
        return str(root.subnet_id) in src.scope_subnet_ids

    @property
    def roots(self) -> list[TargetAddr]:
        return self.scenario.roots

    @property
    def is_renumber(self) -> bool:
        return self.scenario.scenario_type == "ip_renumber"
