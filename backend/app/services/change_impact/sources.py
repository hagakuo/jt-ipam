"""來源能力矩陣與時效（規格 §4.2）。

每個已設定的整合列出：啟用與否、能力、最後成功同步、錯誤、時效分類。時效門檻是
max(2 × 同步間隔, 15 分鐘)；`last_sync_at` 在部分區段失敗時也會更新，所以 `last_error` 非空＝部分成功。

`not_configured` 表示這類資料沒有納入觀測 —— 不可以當成「沒有依賴」。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# 分析類別 → 會被哪些整合餵資料。ipam、config、cert、physical 是 jt-ipam 自己的資料，一定有
CATEGORIES = ("ipam", "dns", "dhcp", "firewall", "nat", "librenms", "virt", "monitoring", "cert", "config", "physical")
# 全域基礎設施：沒有全域讀取權的帳號看不到（結果標 permission_limited）
GLOBAL_CATEGORIES = frozenset({"dns", "dhcp", "firewall", "nat", "librenms", "virt"})
# 只有管理員看得到的資料
ADMIN_CATEGORIES = frozenset({"monitoring", "cert"})


@dataclass
class SourceStatus:
    kind: str                       # opnsense / dns_server / kea_dhcp …
    id: uuid.UUID
    name: str
    categories: tuple[str, ...]
    last_sync_at: datetime | None
    last_error: str | None
    interval_seconds: int | None
    scope_subnet_ids: list[str] | None
    freshness: str = "unknown"
    capabilities: list[str] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"{self.kind}:{self.id}"

    def manifest(self) -> dict[str, Any]:
        return {"kind": self.kind, "id": str(self.id), "name": self.name, "categories": list(self.categories),
                "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
                "has_error": bool(self.last_error), "freshness": self.freshness,
                "interval_seconds": self.interval_seconds, "scoped": bool(self.scope_subnet_ids),
                "capabilities": self.capabilities}


def classify(last_sync_at: datetime | None, last_error: str | None, interval: int | None, now: datetime,
             *, default_stale_hours: int = 24) -> str:
    if last_sync_at is None:
        return "failed" if last_error else "never_synced"
    limit = timedelta(seconds=max(2 * interval, 900)) if interval else timedelta(hours=default_stale_hours)
    if now - last_sync_at > limit:
        return "stale"
    return "partial" if last_error else "fresh"


# (模型路徑, 類別, kind, 分析類別, 間隔欄位, 額外條件與能力)
_SPECS: tuple[tuple[str, str, str, tuple[str, ...], str, tuple[str, ...]], ...] = (
    ("app.models.dns", "DNSServer", "dns_server", ("dns",), "sync_interval_seconds", ("a_aaaa", "ptr")),
    ("app.models.dhcp_standalone", "KeaDhcpServer", "kea_dhcp", ("dhcp",), "sync_interval_seconds",
     ("reservations", "leases", "pools", "ipv4_only")),
    ("app.models.dhcp_standalone", "IscDhcpServer", "isc_dhcp", ("dhcp",), "report_interval_seconds",
     ("reservations", "leases", "pools", "ipv4_only")),
    ("app.models.windows_dhcp", "WindowsDhcpServer", "windows_dhcp", ("dhcp",), "sync_interval_seconds",
     ("reservations", "leases", "pools")),
    ("app.models.firewall", "OPNsenseFirewall", "opnsense", ("firewall", "nat", "dhcp"), "sync_interval_seconds",
     ("rules", "aliases", "nat")),
    ("app.models.pfsense", "PfSenseFirewall", "pfsense", ("firewall", "dhcp"), "sync_interval_seconds",
     ("rules", "aliases")),
    ("app.models.fortigate", "FortiGateFirewall", "fortigate", ("firewall", "nat", "dhcp"), "sync_interval_seconds",
     ("rules", "address_objects", "vdom")),
    ("app.models.paloalto", "PaloAltoFirewall", "paloalto", ("firewall", "nat", "dhcp"), "sync_interval_seconds",
     ("rules", "address_objects", "vsys")),
    ("app.models.mikrotik", "MikroTikRouter", "mikrotik", ("firewall", "nat", "dhcp"), "sync_interval_seconds",
     ("rules", "address_lists")),
    ("app.models.librenms", "LibreNMSInstance", "librenms", ("librenms", "monitoring"), "sync_interval_seconds",
     ("devices", "arp", "fdb")),
    ("app.models.virt", "ProxmoxInstance", "proxmox", ("virt",), "sync_interval_seconds", ("vms", "interfaces")),
    ("app.models.esxi", "ESXiInstance", "esxi", ("virt",), "sync_interval_seconds", ("vms", "interfaces")),
    ("app.models.zabbix", "ZabbixInstance", "zabbix", ("monitoring",), "sync_interval_seconds", ("hosts",)),
    ("app.models.wazuh", "WazuhInstance", "wazuh", ("monitoring",), "sync_interval_seconds", ("agents",)),
    ("app.models.ocs", "OcsServer", "ocs", ("monitoring",), "sync_interval_seconds", ("inventory",)),
)


async def collect_sources(session: AsyncSession, *, now: datetime | None = None,
                          default_stale_hours: int = 24) -> list[SourceStatus]:
    """所有「已啟用」的整合與其時效。停用的整合不算來源（也不算缺口）。"""
    import importlib
    now = now or datetime.now(UTC)
    out: list[SourceStatus] = []
    for mod, cls, kind, cats, interval_attr, caps in _SPECS:
        model = getattr(importlib.import_module(mod), cls)
        rows = (await session.execute(select(model).where(model.enabled.is_(True)))).scalars().all()
        for r in rows:
            interval = getattr(r, interval_attr, None)
            scope = getattr(r, "scope_subnet_ids", None)
            # 防火牆的 DHCP／NAT 要另外開，沒開的那一類不算這台的能力
            eff = tuple(c for c in cats if not (
                (c == "dhcp" and kind in ("opnsense", "pfsense", "fortigate", "paloalto", "mikrotik")
                 and not getattr(r, "sync_dhcp", False))
                or (c == "nat" and kind in ("opnsense", "fortigate", "paloalto", "mikrotik")
                    and not getattr(r, "sync_nat", False))))
            st = SourceStatus(kind=kind, id=r.id, name=str(getattr(r, "name", "") or kind), categories=eff,
                              last_sync_at=r.last_sync_at, last_error=r.last_error,
                              interval_seconds=int(interval) if interval else None,
                              scope_subnet_ids=[str(x) for x in scope] if scope else None,
                              capabilities=list(caps))
            st.freshness = classify(st.last_sync_at, st.last_error, st.interval_seconds, now,
                                    default_stale_hours=default_stale_hours)
            out.append(st)
    return out


def by_category(sources: list[SourceStatus]) -> dict[str, list[SourceStatus]]:
    out: dict[str, list[SourceStatus]] = {c: [] for c in CATEGORIES}
    for s in sources:
        for c in s.categories:
            out.setdefault(c, []).append(s)
    return out


def watermarks(sources: list[SourceStatus]) -> dict[str, Any]:
    """來源水位：核准之後任一來源同步出新資料，就要求重跑（規格 §9）。"""
    return {s.ref: s.last_sync_at.isoformat() if s.last_sync_at else None for s in sources}
