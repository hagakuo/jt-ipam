"""IP 詳細頁的「探測」（只有管理員能用）。

由負責該子網路的掃描代理對這個 IP 做非侵入式識別（見 services/ip_identify 與代理端
`_job_run_identify`），結果經工作佇列回來。沿用工具頁的代理探測佇列：代理只由內往外連，
後端不會主動連到任何主機。

- 目標固定是這筆 IP 記錄的位址，使用者不能指定別的目標
- 以位址探測（`/identify/ip/{ip}`，給異常偵測的「未授權 IP」這類 IPAM 還沒有記錄的位址）：
  位址必須落在 IPAM 管理的子網路內、由那個子網路的代理執行；重疊網段分不出是哪一邊就拒絕
- 同一個 IP 同時只能有一個探測在排隊或執行
- 每次發起都寫稽核
"""
from __future__ import annotations

import ipaddress
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.ui_error import detail_of, ui_detail
from app.models.address import IPAddress
from app.models.agent_probe_job import STATUS_DONE, STATUS_PENDING, STATUS_RUNNING, AgentProbeJob
from app.models.scan_agent import ScanAgent
from app.models.subnet import Subnet
from app.services import ip_identify
from app.services.agent_probe import ProbeJobError, create_job, expire_stale
from app.services.oui import vendor_for_mac
from app.services.recog import get_matcher as get_recog_matcher

router = APIRouter(prefix="/addresses", tags=["addresses"], dependencies=[Depends(require_admin)])
# 以位址探測：IPAM 沒有記錄、但在管理網段內的位址（見 _resolve_target）
ip_router = APIRouter(prefix="/identify", tags=["addresses"], dependencies=[Depends(require_admin)])


def _ip_text(ip: IPAddress) -> str:
    return str(ip.ip).split("/", 1)[0]


def _jobs_of(ip_text: str):  # type: ignore[no-untyped-def]
    return select(AgentProbeJob).where(
        AgentProbeJob.kind == "identify",
        AgentProbeJob.params["targets"][0].astext == ip_text)


async def _ip_or_404(session: AsyncSession, address_id: uuid.UUID) -> IPAddress:
    ip = await session.get(IPAddress, address_id)
    if ip is None:
        raise HTTPException(status_code=404, detail="Address not found")
    return ip


async def _brief(session: AsyncSession, job: AgentProbeJob, mac_vendor: str | None,
                 guest: str | bool | None = False, *, mac: str | None = None) -> dict[str, Any]:
    """清單用的精簡版：不帶整包原始結果，但帶摘要（清單上就看得出是什麼）。
    `guest`：清單裡每筆都是同一個 IP，由呼叫端查一次傳進來；沒給就自己查。
    `mac`：查出 `mac_vendor` 的 MAC（隨機 MAC、虛擬網卡的廠牌不拿來推類型）。"""
    agent = await session.get(ScanAgent, job.agent_id)
    out: dict[str, Any] = {
        "job_id": str(job.id), "status": job.status,
        "error": job.error, "error_code": None,
        "agent_name": agent.name if agent else None,
        "created_at": job.created_at, "claimed_at": job.claimed_at, "finished_at": job.finished_at,
        "summary": None,
    }
    # 舊版代理不認得這個探測種類（自動更新前）：講清楚是代理版本，而不是丟一句英文
    if job.error and job.error.startswith("unsupported probe"):
        out["error_code"] = "identify_agent_outdated"
    from app.services.agent_probe import CANCELLED_ERROR
    if job.error == CANCELLED_ERROR:
        out["error_code"] = "identify_cancelled"
    if job.status == STATUS_DONE and isinstance(job.result, dict):
        if guest is False:
            from app.services.identify_tasks import job_is_virtual_guest
            guest = await job_is_virtual_guest(session, job)
        out["summary"] = ip_identify.summarize(job.result, mac_vendor=mac_vendor,
                                               recog=await get_recog_matcher(session),
                                               virtual_guest=guest, mac=mac)
    return out


async def _job_out(session: AsyncSession, ip_text: str, job: AgentProbeJob,
                   mac_vendor: str | None, ipa: IPAddress | None = None, *,
                   mac: str | None = None) -> dict[str, Any]:
    if mac is None and ipa is not None and ipa.mac:
        mac = str(ipa.mac)
    out = await _brief(session, job, mac_vendor, mac=mac)
    if ipa is not None and out["summary"] is not None:
        # IP 記錄上的類型還會對照 IPAM 已知的事實（裝置記錄、LibreNMS、電腦上的代理、虛擬化平台）：
        # 探測頁也講出最後採用的是什麼、依據什麼，兩個畫面才不會各說各話
        from app.core.os_fingerprint import normalize_os
        from app.services.device_identity import ipam_facts, resolve_kind
        os_text = out["summary"].get("os")
        kind, reason = resolve_kind(out["summary"]["device_type"], await ipam_facts(session, ipa),
                                    os_family=normalize_os(os_text) if os_text else None)
        if reason is not None:
            out["summary"]["ipam"] = {"kind": kind, "reason": reason}
    out["result"] = job.result
    out["progress"] = job.progress
    out["changes"] = None
    if job.status == STATUS_DONE and isinstance(job.result, dict):
        # 跟上一次完成的探測比
        prev = (await session.execute(_jobs_of(ip_text).where(
            AgentProbeJob.status == STATUS_DONE,
            AgentProbeJob.created_at < job.created_at,
        ).order_by(AgentProbeJob.created_at.desc()).limit(1))).scalars().first()
        if prev is not None and isinstance(prev.result, dict):
            # 上一次的摘要用同一組條件算（IP 記錄的 MAC、Recog、是不是虛擬機），比的才是同一件事
            from app.services.identify_tasks import job_is_virtual_guest
            prev_summary = ip_identify.summarize(prev.result, mac_vendor=mac_vendor,
                                                 recog=await get_recog_matcher(session),
                                                 virtual_guest=await job_is_virtual_guest(session, prev), mac=mac)
            out["changes"] = {"previous_job_id": str(prev.id), "previous_at": prev.created_at,
                              **ip_identify.changes_between(prev.result, job.result, prev_summary, out["summary"])}
    return out




async def _start(session: AsyncSession, request: Request, user: Any, *, ip_text: str,
                 subnet: Subnet | None, ip: IPAddress | None) -> dict[str, Any]:
    """發起一次探測（兩種進入點共用）：由子網路的代理執行、同一位址同時只能一個、寫稽核。"""
    agent = await session.get(ScanAgent, subnet.scan_agent_id) if subnet and subnet.scan_agent_id else None
    if agent is None or not agent.enabled:
        raise HTTPException(409, detail=ui_detail(
            "identify_no_agent", "這個子網路沒有指定掃描代理，無法探測",
            subnet=str(subnet.cidr) if subnet else ""))

    await expire_stale(session)
    busy = (await session.execute(_jobs_of(ip_text).where(
        AgentProbeJob.status.in_((STATUS_PENDING, STATUS_RUNNING))).limit(1))).scalars().first()  # bounded: two statuses
    if busy is not None:
        raise HTTPException(409, detail=ui_detail(
            "identify_in_progress", "這個 IP 已經有探測在進行中", job_id=str(busy.id)))

    try:
        job = await create_job(session, agent_id=agent.id, kind="identify",
                               params={"targets": ip_text}, requested_by=user.id)
    except ProbeJobError as exc:
        raise HTTPException(400, detail=detail_of(exc, "probe_job_error")) from exc
    # 「作業」頁上的那一筆（完成時通知發起人），見 services/identify_tasks
    from app.services.identify_tasks import on_created
    await on_created(session, job=job, ip_text=ip_text, ip=ip, user=user, agent=agent)

    await append_audit(
        session,
        actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="ip_address",
        object_id=str(ip.id) if ip is not None else None,
        action="identify",
        diff={"ip": ip_text, "agent": agent.name, "job_id": str(job.id),
              **({"subnet": str(subnet.cidr)} if ip is None and subnet is not None else {})},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    return {"job_id": str(job.id), "agent_id": str(agent.id), "agent_name": agent.name,
            "status": job.status}


@router.post("/{address_id}/identify", status_code=status.HTTP_202_ACCEPTED)
async def start_identify(
    address_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    ip = await _ip_or_404(session, address_id)
    subnet = await session.get(Subnet, ip.subnet_id)
    return await _start(session, request, user, ip_text=_ip_text(ip), subnet=subnet, ip=ip)


@router.get("/{address_id}/identify")
async def latest_identify(
    address_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """這個 IP 最近一次的探測（重新打開畫面時接著顯示）。沒有就回 job_id=null。"""
    ip = await _ip_or_404(session, address_id)
    await expire_stale(session)
    await session.commit()
    job = (await session.execute(_jobs_of(_ip_text(ip)).order_by(
        AgentProbeJob.created_at.desc()).limit(1))).scalars().first()
    if job is None:
        return {"job_id": None}
    return await _job_out(session, _ip_text(ip), job, await vendor_for_mac(session, ip.mac), ip)


@router.get("/{address_id}/identify/history")
async def identify_history(
    address_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = 50,
) -> dict[str, Any]:
    """這個 IP 的歷次探測（新到舊）。每次的結果都保留，日後可以點回來看。"""
    ip = await _ip_or_404(session, address_id)
    await expire_stale(session)
    await session.commit()
    rows = (await session.execute(_jobs_of(_ip_text(ip)).order_by(
        AgentProbeJob.created_at.desc()).limit(max(1, min(limit, 200))))).scalars().all()
    mv = await vendor_for_mac(session, ip.mac)
    from app.services.fw_lookup import virtual_guest_kind
    guest = await virtual_guest_kind(session, _ip_text(ip), str(ip.mac) if ip.mac else None)
    return {"items": [await _brief(session, j, mv, guest, mac=str(ip.mac) if ip.mac else None) for j in rows]}


async def _cancel(session: AsyncSession, request: Request, user: Any, *, ip_text: str, job_id: uuid.UUID,
                  ip_id: uuid.UUID | None) -> dict[str, Any]:
    """取消一次探測（兩種進入點共用）：只有等待中或執行中的可以取消，寫稽核。"""
    from app.services.agent_probe import cancel_job
    await expire_stale(session)
    job = (await session.execute(_jobs_of(ip_text).where(AgentProbeJob.id == job_id))).scalars().first()
    if job is None:
        raise HTTPException(status_code=404, detail="Probe not found")
    if not await cancel_job(session, job):
        raise HTTPException(409, detail=ui_detail("identify_not_running", "這次探測已經結束，不能取消"))
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="ip_address", object_id=str(ip_id) if ip_id is not None else None,
        action="identify_cancel", diff={"ip": ip_text, "job_id": str(job_id)},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    return {"ok": True}


@router.post("/{address_id}/identify/{job_id}/cancel")
async def cancel_identify(
    address_id: uuid.UUID,
    job_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    ip = await _ip_or_404(session, address_id)
    return await _cancel(session, request, user, ip_text=_ip_text(ip), job_id=job_id, ip_id=ip.id)


@router.get("/{address_id}/identify/{job_id}")
async def get_identify(
    address_id: uuid.UUID,
    job_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    ip = await _ip_or_404(session, address_id)
    await expire_stale(session)
    await session.commit()
    job = (await session.execute(_jobs_of(_ip_text(ip)).where(AgentProbeJob.id == job_id))).scalars().first()
    if job is None:
        raise HTTPException(status_code=404, detail="Probe not found")
    return await _job_out(session, _ip_text(ip), job, await vendor_for_mac(session, ip.mac), ip)


# ─────────────────── 以位址探測 ───────────────────

class _Target:
    """以位址探測的目標：位址、負責的子網路、（若已登記）那筆 IP 記錄。"""

    def __init__(self, ip_text: str, subnet: Subnet, record: IPAddress | None, record_count: int) -> None:
        self.ip_text, self.subnet, self.record = ip_text, subnet, record
        self.record_count = record_count


async def _resolve_target(session: AsyncSession, raw: str) -> _Target:
    """位址 → 負責它的子網路。

    - 只接受單一位址（不接受主機名稱、網段、區間）；IPv4 的網路位址／廣播位址不接受
    - 必須落在 IPAM 的子網路內（未封存），取最小的那一層；拿來掃外面的主機一律 404
    - 同一層有好幾個子網路（重疊網段：兩個單位共用同一個 CIDR）而且不是同一個代理 →
      分不出是哪一邊的主機，拒絕，不可以挑一個就掃
    """
    try:
        addr = ipaddress.ip_address(raw.strip())
    except ValueError as exc:
        raise HTTPException(400, detail=ui_detail(
            "identify_bad_target", "只能探測單一 IP 位址", target=raw[:64])) from exc
    ip_text = str(addr)
    rows = (await session.execute(text("""
        SELECT id, masklen(cidr) AS ml FROM subnets
         WHERE archived_at IS NULL AND cidr >>= CAST(:ip AS inet)
         ORDER BY masklen(cidr) DESC
    """), {"ip": ip_text})).all()
    if not rows:
        raise HTTPException(404, detail=ui_detail(
            "identify_not_managed", "這個位址不在 IPAM 管理的子網路內，無法探測", ip=ip_text))
    best = [r.id for r in rows if r.ml == rows[0].ml]
    subnets = [s for s in [await session.get(Subnet, sid) for sid in best] if s is not None]
    net = ipaddress.ip_network(str(subnets[0].cidr), strict=False)
    if net.version == 4 and net.prefixlen < 31 and addr in (net.network_address, net.broadcast_address):
        raise HTTPException(400, detail=ui_detail(
            "identify_bad_target", "只能探測單一 IP 位址", target=ip_text))
    if len({s.scan_agent_id for s in subnets}) > 1:
        raise HTTPException(409, detail=ui_detail(
            "identify_ambiguous", "有好幾個重疊的子網路包含這個位址，分不出是哪一邊的主機",
            ip=ip_text, subnets=", ".join(str(s.cidr) for s in subnets)))
    subnet = subnets[0]
    record = (await session.execute(select(IPAddress).where(
        IPAddress.subnet_id.in_([s.id for s in subnets]),  # bounded: subnets containing one address
        text("host(ip_addresses.ip) = :ip").bindparams(ip=ip_text)).limit(2))).scalars().all()
    # 重複的 IP 記錄（同一個位址好幾筆）不挑一筆來掛：作業只掛位址
    return _Target(ip_text, subnet, record[0] if len(record) == 1 else None, len(record))


async def _arp_vendor(session: AsyncSession, ip_text: str) -> tuple[str | None, str | None]:
    """沒有 IP 記錄時，用 ARP 最近看到的 MAC 查廠商（判斷裝置類型用得到）→（廠商, MAC）。"""
    from app.models.librenms import ARPEntry
    mac = (await session.execute(select(ARPEntry.mac).where(
        text("host(arp_entries.ip) = :ip").bindparams(ip=ip_text)).order_by(
        ARPEntry.last_seen_at.desc()).limit(1))).scalar()
    return (await vendor_for_mac(session, str(mac)), str(mac)) if mac else (None, None)


async def _vendor_of(session: AsyncSession, t: _Target) -> tuple[str | None, str | None]:
    """（廠商, 查廠商用的 MAC）：IP 記錄的 MAC，沒有的話 ARP 最近看到的。"""
    if t.record is not None and t.record.mac:
        return await vendor_for_mac(session, t.record.mac), str(t.record.mac)
    return await _arp_vendor(session, t.ip_text)


@ip_router.get("/ip/{ip}")
async def identify_target(
    ip: str,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """畫面標題用：位址、子網路、負責的代理；已登記的話帶出那筆記錄（畫面改用記錄的探測頁）。"""
    t = await _resolve_target(session, ip)
    agent = await session.get(ScanAgent, t.subnet.scan_agent_id) if t.subnet.scan_agent_id else None
    # ARP 最後一次看到它（未授權 IP 就是從這裡來的）：探測時沒回應，對照這個時間才知道是剛關機還是早就不在
    from app.models.librenms import ARPEntry
    arp = (await session.execute(select(ARPEntry.last_seen_at, ARPEntry.source).where(
        text("host(arp_entries.ip) = :ip").bindparams(ip=t.ip_text)).order_by(
        ARPEntry.last_seen_at.desc()).limit(1))).first()
    return {"ip": t.ip_text, "subnet_id": str(t.subnet.id), "subnet_cidr": str(t.subnet.cidr),
            "arp_last_seen": arp[0] if arp else None, "arp_source": arp[1] if arp else None,
            "agent_name": agent.name if agent else None,
            "address_id": str(t.record.id) if t.record is not None else None,
            # 0＝IPAM 沒有記錄（畫面標「未登記」）；>1＝重複記錄，不代表未登記
            "record_count": t.record_count}


@ip_router.post("/ip/{ip}", status_code=status.HTTP_202_ACCEPTED)
async def start_identify_by_ip(
    ip: str,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    t = await _resolve_target(session, ip)
    return await _start(session, request, user, ip_text=t.ip_text, subnet=t.subnet, ip=t.record)


@ip_router.get("/ip/{ip}/history")
async def identify_history_by_ip(
    ip: str,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = 50,
) -> dict[str, Any]:
    t = await _resolve_target(session, ip)
    await expire_stale(session)
    await session.commit()
    rows = (await session.execute(_jobs_of(t.ip_text).order_by(
        AgentProbeJob.created_at.desc()).limit(max(1, min(limit, 200))))).scalars().all()
    mv, vmac = await _vendor_of(session, t)
    from app.services.fw_lookup import is_virtual_guest
    mac = t.record.mac if t.record is not None else None
    guest = await is_virtual_guest(session, t.ip_text, str(mac) if mac else None)
    return {"items": [await _brief(session, j, mv, guest, mac=vmac) for j in rows]}


@ip_router.post("/ip/{ip}/{job_id}/cancel")
async def cancel_identify_by_ip(
    ip: str,
    job_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    t = await _resolve_target(session, ip)
    return await _cancel(session, request, user, ip_text=t.ip_text, job_id=job_id,
                         ip_id=t.record.id if t.record is not None else None)


@ip_router.get("/ip/{ip}/{job_id}")
async def get_identify_by_ip(
    ip: str,
    job_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    t = await _resolve_target(session, ip)
    await expire_stale(session)
    await session.commit()
    job = (await session.execute(_jobs_of(t.ip_text).where(AgentProbeJob.id == job_id))).scalars().first()
    if job is None:
        raise HTTPException(status_code=404, detail="Probe not found")
    mv, vmac = await _vendor_of(session, t)
    return await _job_out(session, t.ip_text, job, mv, mac=vmac)
