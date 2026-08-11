"""RIPE / TWNIC 網段匯入端點。

兩條路，因為單一條做不完：

- **線上查詢（RDAP）** `POST /import/rdap/preview|commit`：輸入 IP 或 CIDR，直接向註冊管理
  機構查。RIPE 走 `rdap.db.ripe.net`；TWNIC 走 `rdap.apnic.net`（台灣網段由 APNIC 自動
  轉到 `twnic.rdap.apnic.net`，TWNIC 是 APNIC 底下的 NIR）。
- **貼上 / 上傳 whois 文字** `POST /import/whois/preview|commit`：解析 whois 純文字。
  **RDAP 查不到「handle → 網段」**（APNIC 的 entity 查詢回 404，RIPE 回的內容也不含
  networks），所以要用 handle 之類的條件找網段時，請自己跑 whois 再把輸出貼進來。

`/import/ripe/*` 是舊的檔案上傳端點，保留相容。
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.models.section import Section
from app.models.subnet import Subnet
from app.schemas.base import StrictModel
from app.services.rdap import RdapError, RdapInputError, lookup_ip
from app.services.ripe_twnic import ImportPlan, planify
from app.services.subnet import (
    SubnetOverlap,
    assert_no_overlap,
    compute_master_subnet,
)

router = APIRouter(prefix="/import", tags=["import"])

_MAX_BYTES = 2 * 1024 * 1024  # 2MB


async def _read_text(file: UploadFile) -> str:
    raw = await file.read()
    if len(raw) > _MAX_BYTES:
        raise HTTPException(413, detail="File too large (max 2 MB)")
    return raw.decode("utf-8-sig", errors="replace")


async def _apply_plans(
    session: AsyncSession, section: Section, plans: list[ImportPlan],
) -> dict[str, object]:
    """把匯入計畫寫成 Subnet。idempotent：與既有網段重疊就跳過。"""
    inserted = 0
    skipped = 0
    errored: list[dict[str, str]] = []
    for plan in plans:
        try:
            await assert_no_overlap(session, cidr=plan.cidr, vrf_id=None)
        except SubnetOverlap:
            skipped += 1
            continue
        try:
            master_id = await compute_master_subnet(session, cidr=plan.cidr, vrf_id=None)
            session.add(Subnet(
                section_id=section.id, cidr=plan.cidr,
                description=plan.description, master_subnet_id=master_id,
            ))
            await session.flush()
            inserted += 1
        except Exception as exc:
            errored.append({"cidr": plan.cidr, "error": str(exc)})
    return {"inserted": inserted, "skipped": skipped, "errored": errored,
            "total_plans": len(plans)}


async def _audit_import(
    session: AsyncSession, user: CurrentUser, request: Request,
    section: Section, action: str, result: dict[str, object],
) -> None:
    await append_audit(
        session,
        actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="section",
        object_id=str(section.id),
        action=action,
        diff={"inserted": result["inserted"], "skipped": result["skipped"],
              "errored": len(result["errored"])},  # type: ignore[arg-type]
        request_id=getattr(request.state, "request_id", None),
    )


# ─────────────────── 線上查詢（RDAP）───────────────────

class _RdapQuery(StrictModel):
    source: Literal["ripe", "twnic"] = "ripe"
    query: Annotated[str, Field(min_length=1, max_length=64)]


class _RdapCommit(_RdapQuery):
    section_id: uuid.UUID


def _rdap_payload(net, plans: list[ImportPlan]) -> dict[str, object]:
    return {
        "count": len(plans),
        "plans": [{"cidr": p.cidr, "description": p.description,
                   "country": p.country, "netname": p.netname} for p in plans],
        "network": {
            "handle": net.handle, "name": net.name, "country": net.country,
            "type": net.net_type, "status": net.status,
            "remarks": net.remarks[:10], "entities": net.entities[:10],
            "source_url": net.source_url,
        },
    }


def _plans_from_rdap(net) -> list[ImportPlan]:
    descr = " / ".join(filter(None, [net.name, net.net_type]))
    return [ImportPlan(cidr=c, description=descr or None,
                       country=net.country, netname=net.name) for c in net.cidrs]


async def _lookup(payload: _RdapQuery) -> tuple[object, list[ImportPlan]]:
    """查詢並轉成計畫。輸入錯誤回 400（用戶端問題），上游問題回 502。"""
    try:
        net = await lookup_ip(payload.source, payload.query)
    except RdapInputError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    except RdapError as exc:
        raise HTTPException(502, detail=str(exc)) from exc
    return net, _plans_from_rdap(net)


@router.post("/rdap/preview", dependencies=[Depends(require_admin)])
async def preview_rdap(payload: _RdapQuery, _user: CurrentUser) -> dict[str, object]:
    """線上查詢 IP / CIDR 的登記資料（不寫入）。"""
    return _rdap_payload(*await _lookup(payload))


@router.post("/rdap/commit", dependencies=[Depends(require_admin)])
async def commit_rdap(
    payload: _RdapCommit,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, object]:
    """線上查詢後，把查到的網段建進指定區段。"""
    section = await session.get(Section, payload.section_id)
    if section is None:
        raise HTTPException(400, detail="Invalid section_id")
    net, plans = await _lookup(payload)
    result = await _apply_plans(session, section, plans)
    await _audit_import(session, user, request, section,
                        f"rdap_import:{payload.source}", result)
    await session.commit()
    result["errored"] = result["errored"][:50]  # type: ignore[index]
    result["source_url"] = net.source_url
    return result


# ─────────────────── 貼上 / 上傳 whois 文字 ───────────────────

class _WhoisText(StrictModel):
    text: Annotated[str, Field(min_length=1, max_length=_MAX_BYTES)]


class _WhoisCommit(_WhoisText):
    section_id: uuid.UUID


@router.post("/whois/preview", dependencies=[Depends(require_admin)])
async def preview_whois(payload: _WhoisText, _user: CurrentUser) -> dict[str, object]:
    """解析貼上的 whois 文字（不寫入）。"""
    plans = planify(payload.text)
    return {"count": len(plans),
            "plans": [{"cidr": p.cidr, "description": p.description,
                       "country": p.country, "netname": p.netname} for p in plans]}


@router.post("/whois/commit", dependencies=[Depends(require_admin)])
async def commit_whois(
    payload: _WhoisCommit,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, object]:
    section = await session.get(Section, payload.section_id)
    if section is None:
        raise HTTPException(400, detail="Invalid section_id")
    result = await _apply_plans(session, section, planify(payload.text))
    await _audit_import(session, user, request, section, "whois_import", result)
    await session.commit()
    result["errored"] = result["errored"][:50]  # type: ignore[index]
    return result


# ─────────────────── 舊的檔案上傳端點（保留相容）───────────────────

@router.post("/ripe/preview", dependencies=[Depends(require_admin)])
async def preview_ripe(
    file: Annotated[UploadFile, File()],
    _user: CurrentUser,
) -> dict[str, object]:
    """預覽：解析 whois 內容，列出即將建立的 subnet（不寫入）。"""
    text = await _read_text(file)
    plans = planify(text)
    return {
        "count": len(plans),
        "plans": [
            {
                "cidr": p.cidr,
                "description": p.description,
                "country": p.country,
                "netname": p.netname,
            }
            for p in plans
        ],
    }


@router.post("/ripe/commit", dependencies=[Depends(require_admin)])
async def commit_ripe(
    file: Annotated[UploadFile, File()],
    section_id: Annotated[uuid.UUID, Form()],
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, object]:
    """寫入：所有解析出的 CIDR 建為新 Subnet 於指定 section。

    idempotent：同 (vrf, cidr) 已存在則 skip。
    """
    section = await session.get(Section, section_id)
    if section is None:
        raise HTTPException(400, detail="Invalid section_id")

    text = await _read_text(file)
    plans = planify(text)

    inserted = 0
    skipped = 0
    errored: list[dict[str, str]] = []

    for plan in plans:
        # 重疊檢查 — 已存在就 skip（idempotent）
        try:
            await assert_no_overlap(session, cidr=plan.cidr, vrf_id=None)
        except SubnetOverlap:
            skipped += 1
            continue
        try:
            master_id = await compute_master_subnet(session, cidr=plan.cidr, vrf_id=None)
            obj = Subnet(
                section_id=section.id,
                cidr=plan.cidr,
                description=plan.description,
                master_subnet_id=master_id,
            )
            session.add(obj)
            await session.flush()
            inserted += 1
        except Exception as exc:
            errored.append({"cidr": plan.cidr, "error": str(exc)})

    await append_audit(
        session,
        actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="section",
        object_id=str(section.id),
        action="ripe_twnic_import",
        diff={"inserted": inserted, "skipped": skipped, "errored": len(errored)},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()

    return {
        "inserted": inserted,
        "skipped": skipped,
        "errored": errored[:50],
        "total_plans": len(plans),
    }
