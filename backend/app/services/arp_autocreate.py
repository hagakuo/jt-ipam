"""依 LibreNMS 的 ARP 表自動建立 IP（GitHub #48，2026-10-01）。

整合設定裡的選項，**預設關**。以前一直不做，原因現在都變成這裡的把關：

1. **ARP 快取很久才清**（使用者特別提醒）。LibreNMS 的 ARP API 不回任何時間欄位，
   我們只知道「這一輪它還在清單裡」。有些設備的 ARP 幾小時到幾天才清（Cisco 預設 4 小時，
   有的要到介面斷線或重開機），再加上 LibreNMS 自己的 discovery 週期，早就離開的設備也會
   一直看起來像「剛剛還在」。所以預設要**交換器 MAC 表（FDB）24 小時內也看過這個 MAC**：
   MAC 表通常 5 分鐘就老化，LibreNMS 的 FDB 又帶了真實的 updated_at，它才能證明這台設備
   最近真的有在講話。沒有 FDB 的環境可以關掉這道（設定頁會講清楚代價）。
2. **重疊網段**：ARP 沒有子網路資訊 → 只建在「唯一且最精確」的既有子網路（不會憑空長出
   子網路）；同一個位址在好幾個子網路都有記錄＝不明確，不猜。整合的「限定子網路範圍」
   正是用來消除歧義的。
3. **雜訊**：代理 ARP（同一個 MAC 對應一大串 IP，是路由器在代答）、廣播／群播／全零 MAC、
   網路位址與廣播位址、同一輪一個 IP 有兩個 MAC（衝突或備援切換，交給 IP 衝突偵測）。
4. **管理員剛釋放的位址**（冷卻期內）不偷偷建回來：它還在用，該出現在「未授權 IP」。
5. **DHCP 動態範圍**預設略過：那段會回收再發給別台，建了只是一直換人。
6. **一輪有上限**：第一次打開時可能有幾萬筆，分批建，剩下的下一輪接著。

建出來的記錄 `discovery_source='librenms_arp'`（畫面標成「自動收錄、未經登記」），寫一筆
「新增」異動記錄。MAC 與 last_seen_arp 由 sync_arp 後面同一段補上（規則同一份）。
**建了不代表上線**：LibreNMS 的 ARP 不會過期，預設不算上線證據（services/evidence.py）。

開了之後私接的設備也會被收錄，而且從此不再出現在「未授權 IP」異常偵測（設定頁要講清楚）。
"""
from __future__ import annotations

import bisect
import ipaddress
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import String, func, select
from sqlalchemy.dialects.postgresql import MACADDR
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.sqlin import in_values
from app.models.address import IPAddress

#: 同一個 MAC 對應這麼多個 IP 以上 → 視為代理 ARP（路由器／防火牆在代答），整串都不建
PROXY_ARP_MIN_IPS = 8
#: 一輪最多建幾筆
MAX_PER_RUN = 500
#: MAC 表要在這段時間內看過（LibreNMS 的 discovery 預設 6 小時一輪，留足餘裕）
FDB_FRESH_HOURS = 24

_ZERO = "00:00:00:00:00:00"
_BCAST = "ff:ff:ff:ff:ff:ff"


def _mac(raw: object) -> str | None:
    """`aa:bb:cc:dd:ee:ff`；不是可用的單播位址就 None。"""
    hexs = "".join(c for c in str(raw or "").lower() if c in "0123456789abcdef")
    if len(hexs) != 12:
        return None
    mac = ":".join(hexs[i:i + 2] for i in range(0, 12, 2))
    if mac in (_ZERO, _BCAST) or int(hexs[:2], 16) & 1:      # 群播位元
        return None
    return mac


def _special(aip: Any) -> bool:
    return bool(aip.is_multicast or aip.is_unspecified or aip.is_loopback
                or aip.is_link_local or aip.is_reserved)


def _not_host(aip: Any, net: Any) -> bool:
    """網路位址、IPv4 廣播位址（/31、/32 與 IPv6 /127、/128 例外）。"""
    if net.version == 4:
        return bool(net.prefixlen <= 30 and aip in (net.network_address, net.broadcast_address))
    return net.prefixlen <= 126 and aip == net.network_address


class _Ranges:
    """DHCP 動態範圍：合併後二分搜尋（大站台可能有上千段）。"""

    def __init__(self, rows: list[tuple[str, str]]) -> None:
        spans: dict[int, list[tuple[int, int]]] = {}
        for start, end in rows:
            try:
                a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
            except ValueError:
                continue
            if a.version != b.version:
                continue
            lo, hi = sorted((int(a), int(b)))
            spans.setdefault(a.version, []).append((lo, hi))
        self._starts: dict[int, list[int]] = {}
        self._ends: dict[int, list[int]] = {}
        for ver, items in spans.items():
            items.sort()
            merged: list[list[int]] = []
            for lo, hi in items:
                if merged and lo <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], hi)
                else:
                    merged.append([lo, hi])
            self._starts[ver] = [m[0] for m in merged]
            self._ends[ver] = [m[1] for m in merged]

    def __contains__(self, aip: Any) -> bool:
        starts = self._starts.get(aip.version)
        if not starts:
            return False
        i = bisect.bisect_right(starts, int(aip)) - 1
        return i >= 0 and int(aip) <= self._ends[aip.version][i]


async def create_from_arp(
    session: AsyncSession, instance: Any, pairs: list[tuple[str, str]], *,
    scope_ids: Any = None, now: datetime | None = None,
) -> dict[str, Any]:
    """依這一輪的 (ip, mac) 建立 IPAM 還沒有的位址；回傳 {"created": n, "skipped": {原因: 筆數}}。

    呼叫端要在 commit 前呼叫（同一個交易）；新建的列已 flush、取得 id。
    """
    from app.models.dhcp import DHCPPoolRange
    from app.models.ip_cooldown import IPCooldown
    from app.models.librenms import FDBEntry
    from app.services.ip_autocreate import addable_subnets, match_existing_many, subnet_index
    from app.services.ip_history import log_change

    skipped: Counter[str] = Counter()
    if not getattr(instance, "auto_create_from_arp", False):
        return {"created": 0, "skipped": {}}
    now = now or datetime.now(UTC)

    # ── 1. 逐 IP 收齊這一輪看到的 MAC（同一個 IP 可能出現在好幾台路由器的 ARP 表）──
    ip_macs: dict[str, set[str]] = {}
    ip_bad: set[str] = set()
    for raw_ip, raw_mac in pairs:
        try:
            ip = ipaddress.ip_address(str(raw_ip).split("/", 1)[0].strip()).compressed
        except ValueError:
            continue
        mac = _mac(raw_mac)
        if mac is None:
            ip_bad.add(ip)
            continue
        ip_macs.setdefault(ip, set()).add(mac)
    mac_ips: dict[str, set[str]] = {}
    for ip, macs in ip_macs.items():
        for m in macs:
            mac_ips.setdefault(m, set()).add(ip)

    # ── 2. 已在 IPAM 的不必建（也不算進略過原因：摘要只講「IPAM 沒有、卻沒建」的那些）；不明確的不猜 ──
    scope_ids = list(scope_ids) if scope_ids else None
    matches = await match_existing_many(session, set(ip_macs) | ip_bad, scope_ids)
    pending: set[str] = set()
    for ip in set(ip_macs) | ip_bad:
        obj, ambiguous = matches.get(ip, (None, False))
        if obj is not None:
            continue
        if ambiguous:
            skipped["ambiguous"] += 1
            continue
        pending.add(ip)

    # ── 3. 只看本地就能判斷的（代理 ARP 看的是這一輪全部的 ARP，包含已登記的位址）──
    cand: dict[str, str] = {}              # ip → mac
    for ip in pending:
        macs = ip_macs.get(ip)
        if not macs:
            skipped["bad_mac"] += 1
            continue
        if len(macs) > 1:
            skipped["mac_conflict"] += 1
            continue
        (mac,) = macs
        if len(mac_ips[mac]) >= PROXY_ARP_MIN_IPS:
            skipped["proxy_arp"] += 1
            continue
        if _special(ipaddress.ip_address(ip)):
            skipped["not_host"] += 1
            continue
        cand[ip] = mac
    if not cand:
        return {"created": 0, "skipped": dict(skipped)}

    # ── 4. 落點子網路：唯一且最精確 ──
    idx = subnet_index(await addable_subnets(session, scope_ids)) if cand else None
    placed: dict[str, tuple[Any, str]] = {}          # ip → (subnet_id, mac)
    for ip, mac in cand.items():
        aip = ipaddress.ip_address(ip)
        hit = idx.pick_net(aip) if idx else None
        if hit is None:
            skipped["no_subnet"] += 1
            continue
        net, sid = hit
        if _not_host(aip, net):
            skipped["not_host"] += 1
            continue
        placed[ip] = (sid, mac)

    # ── 5. ARP 快取很久才清：MAC 表最近要看過 ──
    if placed and getattr(instance, "arp_create_require_fdb", True):
        cutoff = now - timedelta(hours=FDB_FRESH_HOURS)
        macs = {m for _sid, m in placed.values()}
        fresh = {str(m) for (m,) in (await session.execute(
            select(FDBEntry.mac).where(in_values(FDBEntry.mac, macs, type_=MACADDR()),
                                       FDBEntry.last_seen_at >= cutoff).distinct())).all()}
        for ip in [ip for ip, (_sid, m) in placed.items() if m not in fresh]:
            skipped["no_recent_fdb"] += 1
            del placed[ip]

    # ── 6. 冷卻期內（管理員剛釋放）──
    if placed:
        host = func.host(IPCooldown.ip)
        cooling = {(sid, str(ip)) for sid, ip in (await session.execute(
            select(IPCooldown.subnet_id, host).where(
                in_values(host, set(placed), type_=String()),
                IPCooldown.cleared_at.is_(None), IPCooldown.until > now))).all()}
        for ip in [ip for ip, (sid, _m) in placed.items() if (sid, ip) in cooling]:
            skipped["cooldown"] += 1
            del placed[ip]

    # ── 7. DHCP 動態範圍 ──
    if placed and getattr(instance, "arp_create_skip_dhcp", True):
        ranges = _Ranges([(a, b) for a, b in (await session.execute(
            select(DHCPPoolRange.start_ip, DHCPPoolRange.end_ip))).all()])
        for ip in [ip for ip in placed if ipaddress.ip_address(ip) in ranges]:
            skipped["dhcp_range"] += 1
            del placed[ip]

    # ── 8. 一輪上限（依子網路、位址排序，每輪結果一致）──
    order = sorted(placed, key=lambda ip: (str(placed[ip][0]), int(ipaddress.ip_address(ip))))
    if len(order) > MAX_PER_RUN:
        skipped["cap"] += len(order) - MAX_PER_RUN
        order = order[:MAX_PER_RUN]

    when = now.astimezone().strftime("%Y-%m-%d %H:%M")
    require_fdb = getattr(instance, "arp_create_require_fdb", True)
    created: list[IPAddress] = []
    for ip in order:
        sid, mac = placed[ip]
        note = (f"此 IP 由 LibreNMS 整合「{instance.name}」於 {when} 同步 ARP 表時自動建立"
                f"（MAC {mac}{'，交換器 MAC 表 24 小時內也看過' if require_fdb else ''}）。")
        obj = IPAddress(subnet_id=sid, ip=ip, state="used", discovery_source="librenms_arp", note=note)
        session.add(obj)
        created.append(obj)
    if created:
        await session.flush()      # autoflush=False：先取得 id，異動記錄與後面補 MAC 才有對象
        for obj in created:
            await log_change(session, ip=obj, event_type="created", source="librenms",
                             note="依 LibreNMS ARP 表自動建立")
    return {"created": len(created), "skipped": dict(skipped)}
