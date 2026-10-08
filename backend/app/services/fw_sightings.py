"""防火牆整合共用：一輪同步裡某個區段（ARP 表、DHCP 租約、VPN 連線）看到的位址，收齊了一次寫。

## 為什麼有這個檔案

OPNsense／pfSense／FortiGate／Palo Alto／MikroTik 以前各有一份幾乎一模一樣的 `_stamp_ip_seen`，
每看到一筆就各做一次：比對 IP、判斷 MAC 優先序（變了還要查上一筆異動記錄）、寫 IP 衝突的證據。
一筆約 4 次查詢 —— 一台防火牆 5 萬筆 ARP 加 5 萬筆租約，一輪就是三四十萬次
（2026-09-30 大量資料測試）。五份複本也是這個專案一再踩到的坑：改了一份，其他四份沒跟上。

用法（每個區段一個）：

    batch = SightingBatch(session, source="opnsense", subnet_ids=scope_ids,
                          lease_run=lease_run, create_in=create_in, hn_run=hn_run)
    for r in rows:
        batch.add(ip, evidence="lease:opnsense", mac=mac, hostname=host)
    results = await batch.flush()      # 每一筆 add() 一個 (有對到或新建, 原本就在)

規則與原本逐筆那一份完全相同：
- 唯一才算：同一個位址在好幾個子網路都有 → 不寫、也不新建
- `subnet_ids`（整合的「限定子網路範圍」）有給就只在裡面找
- `create_in`（開了自動建立 IP）才建，而且落點子網路要唯一
- 證據逐來源記在 `arp_seen`（`arp:/lease:/vpn:<廠牌>`）；靜態 ARP（permanent）不算上線證據
- MAC 依來源優先序決定要不要覆寫，覆寫就寫異動記錄
- IP 衝突偵測的觀測只收 ARP 表的動態項目
- 有 `hn_run` 時每一筆都要回報主機名稱（沒有名稱＝這個 IP 目前沒有名稱）
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address import IPAddress


@dataclass(slots=True)
class _Row:
    ip: str | None
    evidence: str | None
    mac: str | None
    hostname: str | None
    permanent: bool
    seen_at: datetime | None
    lease: bool


def _norm_ip(raw: object) -> str | None:
    """位址字串 → 與資料庫相同的標準寫法（去掉遮罩、IPv6 小寫壓縮）；不是位址就 None。"""
    s = str(raw or "").strip().split("/", 1)[0]
    if not s:
        return None
    try:
        return ipaddress.ip_address(s).compressed
    except ValueError:
        return None


class SightingBatch:
    """見模組說明。"""

    def __init__(self, session: AsyncSession, *, source: str, subnet_ids: Any = None,
                 lease_run: Any = None, create_in: Any = None, hn_run: Any = None) -> None:
        self.session = session
        self.source = source
        self.subnet_ids = list(subnet_ids) if subnet_ids else None
        self.lease_run = lease_run
        self.create_in = create_in
        self.hn_run = hn_run
        self._rows: list[_Row] = []

    def add(self, ip: object, *, evidence: str | None, mac: str | None = None, hostname: str | None = None,
            permanent: bool = False, seen_at: datetime | None = None, lease: bool = True) -> None:
        """`evidence=None`：不記上線證據（DHCP 伺服器的租約只說「發給過誰」）。
        `lease=False`：這一筆不算有租約（例如沒人在用的保留位址），名稱與 MAC 照樣處理。"""
        self._rows.append(_Row(_norm_ip(ip), evidence, mac, hostname, permanent, seen_at, lease))

    async def flush(self) -> list[tuple[bool, bool]]:
        from app.services import arp_seen as arp_seen_svc
        from app.services.arp_evidence import normalize as norm_mac
        from app.services.arp_precedence import (
            ARP_SOURCES,
            _apply,
            load_precedence,
            pick_mac,
            would_take,
        )
        from app.services.hostname import apply_observations_bulk
        from app.services.ip_autocreate import match_existing_many, subnet_for_ip_str
        from app.services.ip_history import latest_changes

        rows, self._rows = self._rows, []
        s = self.session
        wanted = {r.ip for r in rows if r.ip}
        matches = await match_existing_many(s, wanted, self.subnet_ids) if wanted else {}
        by_ip: dict[str, IPAddress] = {ip: obj for ip, (obj, _amb) in matches.items() if obj is not None}
        created: set[str] = set()
        if self.create_in is not None:
            for ip in wanted:
                obj, ambiguous = matches.get(ip, (None, False))
                if obj is not None or ambiguous:
                    continue
                sid = subnet_for_ip_str(self.create_in, ip)
                if sid is None:
                    continue
                by_ip[ip] = IPAddress(subnet_id=sid, ip=ip, state="used", discovery_source=self.source)
                s.add(by_ip[ip])
                created.add(ip)
            if created:
                await s.flush()        # autoflush=False：先取得 id，後面的觀測寫入才有對象

        src = self.source if self.source in ARP_SOURCES else "scanner"
        order, disabled = await load_precedence(s)
        results: list[tuple[bool, bool]] = []
        reported: dict[Any, tuple[IPAddress, dict[str, list[Any]]]] = {}
        arp_obs: list[dict[str, Any]] = []
        names: dict[Any, str] = {}
        for r in rows:
            ipa = by_ip.get(r.ip) if r.ip else None
            if ipa is None:
                results.append((False, False))
                continue
            results.append((True, r.ip not in created))
            if r.evidence:
                arp_seen_svc.stamp(ipa, r.evidence, r.seen_at, permanent=r.permanent)
            if self.lease_run is not None and r.lease:
                self.lease_run.saw(ipa)
            if r.mac:
                m = norm_mac(r.mac)
                if m:     # 佔位值（00:00:00:00:00:00 這類沒解析完成的 ARP）不算回報了 MAC
                    reported.setdefault(ipa.id, (ipa, {}))[1].setdefault(
                        m.replace(":", ""), [0, r.mac.strip().lower()])[0] += 1
                # IP 衝突偵測的依據：只有 ARP 表的動態項目算（issue #41），不管來源優先序
                if (m and not r.permanent and (r.evidence or "").startswith("arp:")
                        and ipa.subnet_id is not None):
                    when = (r.seen_at or datetime.now(UTC)).astimezone(UTC)
                    arp_obs.append({"ip": r.ip, "mac": m, "source": (r.evidence or "")[:16],
                                    "subnet_id": ipa.subnet_id, "first_seen_at": when, "last_seen_at": when})
            if self.hn_run is not None:
                self.hn_run.report(ipa, r.hostname)
            elif r.hostname:
                names[ipa.id] = r.hostname

        # 同一批裡同一個 IP 報了好幾個 MAC（ARP 是新的那台、租約還是上一台）：每個 IP 只決定一次（pick_mac）。
        # 以前依序套用，每一輪都換過去再換回來
        mac_cands: list[tuple[IPAddress, str]] = []
        for ipa, macs in reported.values():
            pick = pick_mac(ipa.mac, {k: v[0] for k, v in macs.items()})
            if pick is not None and would_take(order, disabled, cur_mac=ipa.mac, cur_source=ipa.mac_source,
                                               mac=macs[pick][1], source=src):
                mac_cands.append((ipa, macs[pick][1]))
        if mac_cands:
            latest = await latest_changes(s, {ipa.id for ipa, _m in mac_cands}, "mac")
            for ipa, mac in mac_cands:
                await _apply(s, ip=ipa, mac=mac, source=src, latest=latest)
        if arp_obs:
            from app.models.librenms import ARPEntry
            from app.services.arp_evidence import _OBSERVED
            ins = insert(ARPEntry)
            await s.execute(ins.on_conflict_do_update(
                index_elements=["ip", "mac", "source", "subnet_id"], index_where=_OBSERVED,
                set_={"last_seen_at": func.greatest(ARPEntry.last_seen_at, ins.excluded.last_seen_at)},
            ), arp_obs)
        if names:
            await apply_observations_bulk(s, source=self.source, wants=names,
                                          ips={i.id: i for i in by_ip.values()})
        return results
