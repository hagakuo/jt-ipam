"""機櫃 U 位視覺化用的 endpoint：拿一個機櫃 + 所有設備 + 占位資訊。"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin, require_object_perm
from app.core.db import get_session
from app.models.address import IPAddress
from app.models.device import Device
from app.models.location import Rack
from app.schemas.base import StrictModel
from app.services.rack import (
    KALLAX_DIVIDER_MM,
    RACK_REF_WIDTH_MM,
    RACK_REF_WIDTH_PX,
    RACK_SLOTS,
    brace_levels,
    floor_default_mm,
    has_open_top,
    kallax_columns,
    level_boards_px,
    level_render_px,
    normalize_finish,
    placeable_levels,
    rack_side_px,
    scaled_board_px,
    v_px_per_mm,
)


def _board_px(rack) -> float:  # type: ignore[no-untyped-def]
    """層板畫出來多厚（px）。層高填的是淨空高，板厚要另外占掉高度。"""
    return scaled_board_px(getattr(rack, "kind", None), getattr(rack, "board_mm", None),
                           getattr(rack, "width_mm", None), getattr(rack, "row_height_mm", None),
                           getattr(rack, "level_heights", None), rack.u_height)


def _floor_px(rack) -> float:  # type: ignore[no-untyped-def]
    """離地高度（px）。機櫃與層架都要有腳 —— 沒有的話底部看起來像被齊平切掉。

    例外是本來就落地的東西（KALLAX 沒有腳）：型態有自己的預設值時照它，0 就是 0。
    """
    kind = getattr(rack, "kind", None)
    mm = getattr(rack, "floor_mm", None)
    dflt = floor_default_mm(kind)
    per_mm = v_px_per_mm(kind)      # 層架寬高同一個比例，機櫃沿用 1U＝28px
    if mm is None and dflt is not None:
        return dflt * per_mm
    if kind == "kallax":
        return float(mm or 0) * per_mm
    px = float(mm) * per_mm if mm else 0.0
    return max(px, 7.0)


def _size(rack) -> tuple[float, list[float]]:  # type: ignore[no-untyped-def]
    """(寬 px, 每一層的高 px)。層架的層高可以一層一層不同，所以列高是一個陣列。"""
    return level_render_px(getattr(rack, "kind", None),
                           getattr(rack, "width_mm", None),
                           getattr(rack, "row_height_mm", None),
                           getattr(rack, "level_heights", None),
                           getattr(rack, "u_height", None))

router = APIRouter(prefix="/racks", tags=["racks"])


class RackDeviceSlot(StrictModel):
    device_id: uuid.UUID
    name: str
    type: str
    vendor: str | None
    model: str | None
    u_position: int   # bottom-most U (1-based, 1 = 最下面)
    u_size: int
    primary_ip: str | None
    rack_face: str | None = None   # front / rear（安裝方向）
    # 橫向格位（issue #31）：起始格 + 跨幾格，網格 RACK_SLOTS(60) 格
    rack_slot: int = 0
    rack_slot_span: int = RACK_SLOTS
    # 層內的垂直格位：層架一層可以疊放、也可以不放滿。0 貼著層板，往上長
    rack_vslot: int = 0
    rack_vslot_span: int = RACK_SLOTS


class RackDiagram(StrictModel):
    rack_id: uuid.UUID
    name: str
    u_height: int
    # issue #30：層架的列是「層」不是 U，寬度與列高也不是標準值 —— 前端照這些畫
    kind: str = "rack"
    render_width_px: float = 250.0
    # 機櫃兩側的走線空間各多寬 px（19 吋設備區之外、外寬多出來的部分）；層架是 0
    render_side_px: float = 0.0
    # 均一層高時的列高（舊欄位，留著給還沒更新的用戶端）。層高逐層不同時這裡是第 1 層的值。
    render_row_px: float = 28.0
    # 每一層的高度 px，由**第 1 層**起算（不是畫面由上往下）。層架的層板一層一層可調。
    render_row_px_list: list[float] = []
    # 木質層架背面的支撐桿跨幾層（0＝不畫）。它是固定 100 公分的鋼條，跨距由寬度決定，
    # 算在後端才不會前後端各算各的。
    brace_levels: int = 0
    # 層架的最上面那片板**上面**也放得了東西（＝第 u_height + 1 層）。機櫃沒有這個位置。
    open_top: bool = False
    # 層板畫出來多厚 px（層高填的是淨空高，板厚另計）
    render_board_px: float = 0.0
    # 最下面那片層板離地多高 px —— 層架是站在腳上的，不畫就會像直接貼在地上被切斷
    render_floor_px: float = 0.0
    # 每一列**底下**那片板的厚度 px，由上往下（畫面順序，含開放頂端那一列）。
    # 以前只有一個 render_board_px；KALLAX 的外框比內隔板厚、LackRack 疊了幾張就有幾片桌面，
    # 不能再當成每片一樣厚。既有型態就是 render_board_px 重複 n 次。
    render_board_px_list: list[float] = []
    # 最上面那一列**之上**的厚度 px（LackRack 的桌面）。其他型態是 0。
    render_top_px: float = 0.0
    # 表面顏色（沒有顏色選項的型態是 None）
    finish: str | None = None
    # KALLAX 有幾欄（其他型態是 1）與內隔板的寬 px
    render_cols: int = 1
    render_divider_px: float = 0.0
    location_id: uuid.UUID | None
    numbering: str = "top-down"
    face: str = "front"
    devices: list[RackDeviceSlot]
    conflicts: list[dict[str, Any]]    # 同一 U 被多 device 佔用 / 越界


@router.get(
    "/{rack_id}/diagram",
    response_model=RackDiagram,
    dependencies=[Depends(require_object_perm("rack", "read", path_param="rack_id"))],
)
async def rack_diagram(
    rack_id: uuid.UUID,
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RackDiagram:
    rack = await session.get(Rack, rack_id)
    if rack is None:
        raise HTTPException(404, detail="Rack not found")

    devices = list(
        (
            await session.execute(
                select(Device)
                .where(Device.rack_id == rack_id)
                .order_by(Device.u_position)
            )
        ).scalars().all()
    )

    # 拼 primary IP（如果有）
    primary_ip_ids = [d.primary_ip_id for d in devices if d.primary_ip_id]
    ip_map: dict[uuid.UUID, str] = {}
    if primary_ip_ids:
        ip_rows = (
            await session.execute(
                select(IPAddress).where(IPAddress.id.in_(primary_ip_ids))  # bounded: devices in one rack
            )
        ).scalars().all()
        for ip in ip_rows:
            ip_map[ip.id] = str(ip.ip).split("/")[0]

    # 沒設 primary_ip 的裝置：退而求其次，抓任一掛在該裝置的 IP（tooltip 也能顯示 IP）
    no_primary = [d.id for d in devices if not d.primary_ip_id]
    fallback_ip: dict[uuid.UUID, str] = {}
    if no_primary:
        fb_rows = (
            await session.execute(
                select(IPAddress)
                .where(IPAddress.device_id.in_(no_primary))  # bounded: devices in one rack
                .order_by(IPAddress.ip)
            )
        ).scalars().all()
        for ip in fb_rows:
            if ip.device_id is not None and ip.device_id not in fallback_ip:
                fallback_ip[ip.device_id] = str(ip.ip).split("/")[0]

    slots: list[RackDeviceSlot] = []
    # 占位以 (安裝方向, U) 為 key：前/後同 U 不算衝突（落地機櫃可前後各掛一台）
    # key=(安裝方向, U, 半格 L/R)：full 同時占 L+R；half 只占一邊 → 一左一右同 U 不衝突
    occupied: dict[tuple[str, int, str], list[tuple[uuid.UUID, int, int]]] = {}
    conflicts: list[dict[str, Any]] = []
    # 可放的位置數：層架比 u_height 多一個（最上面那片板的上面）
    _limit = placeable_levels(getattr(rack, "kind", None), rack.u_height)

    for d in devices:
        if d.u_position is None or d.u_size is None:
            # 未設定 U 位的設備不畫；給 conflict 報告
            conflicts.append({
                "type": "unpositioned",
                "device_id": str(d.id),
                "name": d.name,
            })
            continue

        # 越界。層架多一個合法位置：最上面那片板的**上面**（第 u_height + 1 層），
        # 這裡漏掉的話放在頂板上的裝置會被當成越界、連畫都不畫。
        if d.u_position < 1 or (d.u_position + d.u_size - 1) > _limit:
            conflicts.append({
                "type": "out_of_bounds",
                "device_id": str(d.id),
                "name": d.name,
                "u_position": d.u_position,
                "u_size": d.u_size,
                "rack_u_height": rack.u_height,
            })
            continue

        # 占位衝突（同安裝方向才算）：逐格標記這台佔掉的橫向格子
        face = d.rack_face or "front"
        slot = d.rack_slot or 0
        span = d.rack_slot_span or RACK_SLOTS
        # 連同層內的垂直區間一起記：層架可以疊放，同一格橫向位置上下錯開就不是衝突
        vslot = int(getattr(d, "rack_vslot", 0) or 0)
        vspan = int(getattr(d, "rack_vslot_span", RACK_SLOTS) or RACK_SLOTS)
        halves = tuple(str(i) for i in range(slot, slot + span))
        for u in range(d.u_position, d.u_position + d.u_size):
            for hh in halves:
                occupied.setdefault((face, u, hh), []).append((d.id, vslot, vslot + vspan))

        slots.append(
            RackDeviceSlot(
                device_id=d.id,
                name=d.name,
                type=d.type,
                vendor=d.vendor,
                model=d.model,
                u_position=d.u_position,
                u_size=d.u_size,
                primary_ip=ip_map.get(d.primary_ip_id) if d.primary_ip_id else fallback_ip.get(d.id),
                rack_face=d.rack_face,
                rack_slot=slot,
                rack_slot_span=span,
                rack_vslot=int(getattr(d, "rack_vslot", 0) or 0),
                rack_vslot_span=int(getattr(d, "rack_vslot_span", RACK_SLOTS) or RACK_SLOTS),
            )
        )

    seen_overlap: set[tuple[str, int, frozenset[str]]] = set()
    for (face, u, _hh), entries in occupied.items():
        if len(entries) < 2:
            continue
        # 同一個橫向格子上有好幾台時，只有**垂直區間也相交**的才算衝突（疊放是合法的）
        clashing: set[uuid.UUID] = set()
        for i, (id_a, a0, a1) in enumerate(entries):
            for id_b, b0, b1 in entries[i + 1:]:
                if a0 < b1 and b0 < a1:
                    clashing.update((id_a, id_b))
        if len(clashing) < 2:
            continue
        key = (face, u, frozenset(str(x) for x in clashing))
        if key in seen_overlap:
            continue
        seen_overlap.add(key)
        conflicts.append({
            "type": "overlap",
            "u": u,
            "face": face,
            "device_ids": sorted(str(x) for x in clashing),
        })

    _w, _rows = _size(rack)
    kind = getattr(rack, "kind", None)
    board_px = _board_px(rack)
    top_px, boards = level_boards_px(kind, rack.u_height, board_px)
    return RackDiagram(
        rack_id=rack.id,
        name=rack.name,
        u_height=rack.u_height,
        kind=getattr(rack, "kind", "rack") or "rack",
        render_width_px=_w,
        render_side_px=rack_side_px(getattr(rack, "kind", None), getattr(rack, "width_mm", None)),
        render_row_px=(_rows[0] if _rows else 28.0),
        render_row_px_list=_rows,
        open_top=has_open_top(getattr(rack, "kind", None)),
        render_board_px=board_px,
        render_floor_px=_floor_px(rack),
        render_board_px_list=boards,
        render_top_px=top_px,
        finish=normalize_finish(kind, getattr(rack, "finish", None)),
        render_cols=kallax_columns(getattr(rack, "width_mm", None)) if kind == "kallax" else 1,
        render_divider_px=(KALLAX_DIVIDER_MM * RACK_REF_WIDTH_PX / RACK_REF_WIDTH_MM
                           if kind == "kallax" else 0.0),
        brace_levels=brace_levels(getattr(rack, "kind", None),
                                  getattr(rack, "width_mm", None),
                                  getattr(rack, "row_height_mm", None),
                                  rack.u_height,
                                  getattr(rack, "level_heights", None)),
        location_id=rack.location_id,
        numbering=rack.numbering,
        face=rack.face,
        devices=slots,
        conflicts=conflicts,
    )


# ─────────────────── 對外嵌入用的 SVG（token 保護、不需登入）───────────────────
#
# 給別的系統（LibreNMS dashboard 的 widget 之類）用 `<img src="…">` 直接顯示。
# 用圖片而不是 iframe：我們送 `frame-ancestors 'none'` 與 `X-Frame-Options: DENY`，
# iframe 本來就會被擋，要開就得針對來源放行 —— 那是點擊劫持的攻擊面，不值得。
#
# 守門與 Graylog DSV 同一個模式：系統層一把 token + 逐機櫃 `expose_svg`，兩個都要成立。
# **預設全關**：機櫃圖會揭露裝置名稱與位置。

@router.get("/{rack_id}/embed.svg", include_in_schema=False)
async def rack_embed_svg(
    rack_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    token: str = "",
) -> Response:
    from app.services.rack_svg import build_rack_svg
    from app.services.system_config import get_rack_embed

    cfg = await get_rack_embed(session)
    if not cfg["enabled"] or not _embed_token_ok(token, cfg["token"]):
        raise HTTPException(status_code=401, detail="Invalid token")

    rack = await session.get(Rack, rack_id)
    if rack is None or not rack.expose_svg:
        # 不存在與「存在但沒開放」要回一樣的東西，否則拿著 token 就能列舉機櫃
        raise HTTPException(status_code=404, detail="Not found")

    rows = (await session.execute(
        select(Device).where(Device.rack_id == rack_id)
    )).scalars().all()
    svg = build_rack_svg(
        rack.name, rack.u_height,
        [{"name": d.name, "type": d.type, "u_position": d.u_position,
          "u_size": d.u_size, "rack_slot": d.rack_slot,
          "rack_slot_span": d.rack_slot_span, "rack_face": d.rack_face,
          "rack_vslot": d.rack_vslot, "rack_vslot_span": d.rack_vslot_span}
         for d in rows],
        kind=getattr(rack, "kind", None),
        width_mm=getattr(rack, "width_mm", None),
        row_height_mm=getattr(rack, "row_height_mm", None),
        level_heights=getattr(rack, "level_heights", None),
        board_mm=getattr(rack, "board_mm", None),
    )
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            # SVG 可以夾帶腳本。我們自己產生的不會，但這張圖會被貼到別人的頁面上，
            # 所以把回應鎖死：不准載入任何外部資源、不准嗅探型別。
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            # 要被別的網站用 <img> 貼上：站台預設的 CORP same-origin 會讓瀏覽器擋下跨站載入
            # （2026-09-30 發現。nginx 模式另有專屬 location，見 deploy/nginx/jt-ipam.conf）
            "Cross-Origin-Resource-Policy": "cross-origin",
        },
    )


def _embed_token_ok(supplied: str, expected: str | None) -> bool:
    """常數時間比對。這是**未登入**端點，token 是唯一守門，比對方式本身也不能洩漏資訊。"""
    import hmac

    if not expected:
        return False
    return hmac.compare_digest((supplied or "").encode(), expected.encode())


# ─────────────────── 嵌入功能的管理設定（admin）───────────────────

class RackEmbedOut(StrictModel):
    enabled: bool
    token: str


class RackEmbedPatch(StrictModel):
    enabled: bool = False
    regenerate_token: bool = False


admin_router = APIRouter(prefix="/system", tags=["system"],
                         dependencies=[Depends(require_admin)])


@admin_router.get("/rack-embed", response_model=RackEmbedOut)
async def get_rack_embed_ep(
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    from app.services.system_config import get_rack_embed

    return await get_rack_embed(session)


@admin_router.put("/rack-embed", response_model=RackEmbedOut)
async def put_rack_embed_ep(
    payload: RackEmbedPatch, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    from app.core.audit import append_audit
    from app.services.system_config import set_rack_embed

    out = await set_rack_embed(
        session, enabled=payload.enabled,
        regenerate_token=payload.regenerate_token,
        updated_by_user_id=uuid.UUID(str(user.id)),
    )
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="system_setting", object_id=None, action="update",
        # 不記 token 本身 —— 稽核記錄不該變成金鑰的另一份副本
        diff={"setting": "rack_embed", "enabled": out["enabled"],
              "token_rotated": payload.regenerate_token},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    return out
