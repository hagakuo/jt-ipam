"""獨立 DHCP 伺服器（Kea／ISC DHCP，issue #45）共用的寫入層。

兩個來源的資料形狀一樣（範圍、保留、目前有效的租約），只是來路不同：Kea 由 jt-ipam 拉
（services/kea_dhcp.py），ISC DHCP 由掃描代理讀檔回報（`ingest_isc_report`）。寫法比照 Windows DHCP：

- 範圍：先刪掉這個來源自己的列再寫（別的來源不動）
- 保留：`replace_reservations`
- 租約：只標記**既有** IP（`match_existing` 唯一才算、不新建）→ 租約旗標、MAC、主機名稱；
  這一輪的資料不完整（例如租約讀不到）就不清任何東西
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPPoolRange


async def write_pools(session: AsyncSession, *, source_type: str, source_id: uuid.UUID,
                      source_name: str, engine: str, pools: list[dict[str, Any]]) -> int:
    now = datetime.now(UTC)
    await session.execute(delete(DHCPPoolRange).where(
        DHCPPoolRange.source_type == source_type, DHCPPoolRange.source_id == source_id))
    n = 0
    for p in pools:
        start, end = p.get("start"), p.get("end")
        if not start or not end:
            continue
        session.add(DHCPPoolRange(
            source_type=source_type, source_id=source_id, source_name=source_name,
            subnet_cidr=p.get("subnet"), start_ip=start, end_ip=end,
            family=6 if ":" in start else 4, source=engine, synced_at=now))
        n += 1
    return n


async def write_reservations(session: AsyncSession, *, source_type: str, source_id: uuid.UUID,
                             source_name: str, engine: str, rows: list[dict[str, Any]]) -> int:
    from app.services.dhcp_reservations import Reservation, replace_reservations
    seen: set[tuple[str, str | None]] = set()
    out: list[Reservation] = []
    for r in rows:
        key = (r["ip"], r.get("mac"))
        if key in seen:
            continue
        seen.add(key)
        out.append(Reservation(ip=r["ip"], mac=r.get("mac"), hostname=r.get("hostname")))
    return await replace_reservations(session, source_type=source_type, source_id=source_id,
                                      source_name=source_name, engine=engine, rows=out)


async def write_leases(session: AsyncSession, *, source_type: str, source_id: uuid.UUID,
                       peers_model: Any, scope_ids: list[Any] | None,
                       leases: list[dict[str, Any]], complete: bool) -> int:
    """租約 → 既有 IP 的租約旗標、MAC、主機名稱。`complete=False` 時這一輪不清任何東西。"""
    from app.services.dhcp_leases import LeaseRun
    from app.services.fw_sightings import SightingBatch
    from app.services.hostname_reports import HostnameRun, enabled_peers

    hn_run = HostnameRun(session, source=source_type, origin=f"{source_type}:{source_id}",
                         peers=await enabled_peers(session, peers_model))
    lease_run = LeaseRun(session, source_type=source_type, source_id=source_id)
    # 整批（以前每筆租約各比對一次 IP、再判斷一次 MAC）；唯一才算：重疊網段同 IP 多筆又沒設範圍時不猜
    batch = SightingBatch(session, source=source_type, subnet_ids=scope_ids,
                          lease_run=lease_run, hn_run=hn_run)
    for le in leases:
        name = le.get("hostname")
        batch.add(le["ip"], evidence=None, mac=le.get("mac"), hostname=name.split(".")[0] if name else None)
    seen = sum(1 for found, _e in await batch.flush() if found)
    await hn_run.finish(complete=complete)
    await lease_run.finish(complete=complete)
    return seen


# ── ISC DHCP：代理回報的資料 ────────────────────────────────────────────────────

def _ip4(v: Any) -> str | None:
    try:
        a = ipaddress.ip_address(str(v or "").strip())
    except ValueError:
        return None
    return str(a) if a.version == 4 else None


def _mac(v: Any) -> str | None:
    hexs = "".join(ch for ch in str(v or "").lower() if ch in "0123456789abcdef")
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2)) if len(hexs) == 12 else None


def clean_report(report: dict[str, Any]) -> dict[str, Any]:
    """代理送來的東西不能直接信：位址要是 IPv4、MAC 要解得出來、字串截短，其餘丟掉。"""
    pools = []
    for p in report.get("pools") or []:
        start, end = _ip4(p.get("start")), _ip4(p.get("end"))
        if not start or not end:
            continue
        if ipaddress.ip_address(start) > ipaddress.ip_address(end):
            start, end = end, start
        try:
            subnet = str(ipaddress.ip_network(str(p.get("subnet")), strict=False)) if p.get("subnet") else None
        except ValueError:
            subnet = None
        pools.append({"subnet": subnet, "start": start, "end": end})
    res = []
    for r in report.get("reservations") or []:
        ip = _ip4(r.get("ip"))
        if ip:
            res.append({"ip": ip, "mac": _mac(r.get("mac")), "hostname": (r.get("hostname") or None) and
                        str(r["hostname"])[:255]})
    leases = []
    for le in report.get("leases") or []:
        ip = _ip4(le.get("ip"))
        if ip:
            leases.append({"ip": ip, "mac": _mac(le.get("mac")),
                           "hostname": (le.get("hostname") or None) and str(le["hostname"])[:255]})
    return {"pools": pools, "reservations": res, "leases": leases}


async def ingest_isc_report(session: AsyncSession, src: Any, report: dict[str, Any]) -> dict[str, Any]:
    """寫入代理讀 dhcpd.conf／dhcpd.leases 的結果。

    檔案讀不到就說讀不到（寫進 last_error），**不當成「沒有資料」**：設定檔讀不到時不清範圍與固定分配，
    租約檔讀不到時不清租約 —— 不然一次權限問題就會把整台的租約標記全部清掉。
    """
    from app.models.dhcp_standalone import IscDhcpServer

    files = report.get("files") or {}
    conf_ok = bool((files.get("conf") or {}).get("ok"))
    leases_ok = bool((files.get("leases") or {}).get("ok"))
    data = clean_report(report)
    counts: dict[str, Any] = {}
    if src.sync_scopes and conf_ok:
        counts["pools"] = await write_pools(session, source_type="isc_dhcp", source_id=src.id,
                                            source_name=src.name, engine="isc", pools=data["pools"])
        counts["reservations"] = await write_reservations(
            session, source_type="isc_dhcp", source_id=src.id, source_name=src.name, engine="isc",
            rows=data["reservations"])
    if src.sync_leases and leases_ok:
        counts["leases"] = await write_leases(
            session, source_type="isc_dhcp", source_id=src.id, peers_model=IscDhcpServer,
            scope_ids=list(src.scope_subnet_ids) if src.scope_subnet_ids else None,
            leases=data["leases"], complete=True)
    problems = []
    for key, ok in (("conf", conf_ok), ("leases", leases_ok)):
        st = files.get(key) or {}
        if not ok:
            problems.append(f"{st.get('path') or key}: {st.get('error') or 'not readable'}")
    src.file_status = {k: {kk: (files.get(k) or {}).get(kk) for kk in ("path", "ok", "error", "size", "mtime")}
                       for k in ("conf", "leases")}
    src.last_summary = {**counts, "reported_pools": len(data["pools"]),
                        "reported_reservations": len(data["reservations"]),
                        "reported_leases": len(data["leases"])}
    src.last_sync_at = datetime.now(UTC)
    src.last_error = "；".join(problems) or None
    return counts


STALE_FACTOR = 3     # 超過回報間隔幾倍沒收到回報就算失聯


async def mark_stale_isc(session: AsyncSession, now: datetime | None = None) -> int:
    """ISC DHCP 是被動等代理回報：代理停了、被移走、主機關機時不會有任何錯誤冒出來。
    超過回報間隔 3 倍沒收到回報 → 寫 last_error（健康告警看的就是它）；收到回報時 ingest 會清掉。"""
    from sqlalchemy import select

    from app.models.dhcp_standalone import IscDhcpServer
    now = now or datetime.now(UTC)
    n = 0
    for src in (await session.execute(select(IscDhcpServer).where(
            IscDhcpServer.enabled.is_(True), IscDhcpServer.agent_id.is_not(None)))).scalars().all():
        limit = src.report_interval_seconds * STALE_FACTOR
        since = src.last_sync_at or src.created_at
        if since is not None and (now - since).total_seconds() > limit:
            minutes = int((now - since).total_seconds() // 60)
            msg = f"no report from the scan agent for {minutes} min (expected every {src.report_interval_seconds // 60 or 1} min)"
            if src.last_error != msg:
                src.last_error = msg
                n += 1
    return n
