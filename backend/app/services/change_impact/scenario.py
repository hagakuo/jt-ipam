"""情境解析：根目標、命名空間、改址參數的合法性（規格 §3.1、§5.1、§5.4）。

- 根目標一律是物件 id（IP 物件或裝置），不接受只給位址字串；同一位址有好幾筆時由畫面讓使用者選
- 改址：同 family、落在目標子網路內、不是網路／廣播（/31、/32 例外）、多播、未指定、迴路、
  沒有 scope 的 IPv6 link-local；跟舊位址相同也不行
- 目標子網路沒給：在舊位址同一個 VRF、使用者看得到的子網路裡找最小的那個；找不到、或同一層有好幾個 → 要使用者選
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.change_impact.matching import special_reason
from app.services.change_impact.model import TargetAddr


class ScenarioError(Exception):
    """建案或分析參數不合法：code 對應前端 errors.<code>，params 給訊息帶入。"""

    def __init__(self, code: str, message: str, status: int = 422, **params: Any) -> None:
        super().__init__(message)
        self.code, self.status, self.params = code, status, params


@dataclass
class Scenario:
    scenario_type: str
    target_type: str
    target_id: uuid.UUID
    target_label: str
    customer_id: uuid.UUID | None
    roots: list[TargetAddr]
    device_id: uuid.UUID | None = None
    device_name: str | None = None
    new_ip: str | None = None
    new_aip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    target_subnet_id: uuid.UUID | None = None
    target_subnet_cidr: str | None = None
    target_vrf_id: uuid.UUID | None = None
    cross_subnet: bool = False

    def payload(self) -> dict[str, Any]:
        """寫進計畫版本與 scenario_hash 的正規化內容（不含顯示用文字以外的推導值）。"""
        return {"scenario_type": self.scenario_type, "target_type": self.target_type,
                "target_id": str(self.target_id),
                "parameters": {"new_ip": self.new_ip,
                               "target_subnet_id": str(self.target_subnet_id) if self.target_subnet_id else None}}


async def _addr_row(session: AsyncSession, ip_id: uuid.UUID) -> TargetAddr | None:
    row = (await session.execute(text("""
        SELECT a.id, host(a.ip) AS ip, a.subnet_id, s.cidr::text AS cidr, s.vrf_id,
               COALESCE(a.customer_id, s.customer_id) AS customer_id, a.hostname, a.mac::text AS mac, a.state
          FROM ip_addresses a JOIN subnets s ON s.id = a.subnet_id
         WHERE a.id = :id
    """), {"id": ip_id})).first()
    if row is None:
        return None
    return TargetAddr(ip_id=row.id, ip_text=row.ip, aip=ipaddress.ip_address(row.ip), subnet_id=row.subnet_id,
                      subnet_cidr=row.cidr, vrf_id=row.vrf_id, customer_id=row.customer_id,
                      hostname=row.hostname, mac=row.mac, state=row.state)


async def _perm(session: AsyncSession, user: Any, object_type: str, object_id: uuid.UUID) -> str:
    from app.services.permission import get_object_permission
    return await get_object_permission(session, user=user, object_type=object_type, object_id=object_id)  # type: ignore[arg-type]


_RANK = {"none": 0, "read": 1, "write": 2, "admin": 3}


async def require_target_access(session: AsyncSession, user: Any, target_type: str, target_id: uuid.UUID,
                                need: str = "read") -> None:
    """看不到就當作不存在（404，不洩漏存在與否）；看得到但權限不夠 → 403。"""
    ot = "ip" if target_type == "ip_address" else "device"
    level = await _perm(session, user, ot, target_id)
    if _RANK[level] < 1:
        raise ScenarioError("impact_target_not_found", "Target not found", status=404)
    if _RANK[level] < _RANK[need]:
        raise ScenarioError("impact_target_forbidden", "Not enough permission on the target", status=403)


async def device_addresses(session: AsyncSession, device_id: uuid.UUID) -> list[TargetAddr]:
    """裝置的所有 IP：掛在這台裝置上的，加上設為主要 IP 的那筆（可能沒掛 device_id）。"""
    ids = [r[0] for r in (await session.execute(text("""
        SELECT a.id FROM ip_addresses a WHERE a.device_id = :d
        UNION
        SELECT d.primary_ip_id FROM devices d WHERE d.id = :d AND d.primary_ip_id IS NOT NULL
    """), {"d": device_id})).all()]
    out = []
    for i in ids:
        t = await _addr_row(session, i)
        if t is not None:
            out.append(t)
    out.sort(key=lambda t: (t.aip.version, int(t.aip)))
    return out


async def build(session: AsyncSession, user: Any, *, scenario_type: str, target_type: str,
                target_id: uuid.UUID, parameters: dict[str, Any] | None = None,
                need: str = "write") -> Scenario:
    """建案、修改與每次分析都走這裡：權限、根目標、參數驗證一次到位。"""
    from app.models.change_impact import SCENARIOS
    parameters = parameters or {}
    if scenario_type not in SCENARIOS:
        raise ScenarioError("impact_invalid_scenario", "Unknown scenario", scenario=scenario_type)
    expected_target = "ip_address" if scenario_type == "ip_renumber" else "device"
    if target_type != expected_target:
        raise ScenarioError("impact_invalid_scenario", "Target type does not fit the scenario",
                            scenario=scenario_type)
    await require_target_access(session, user, target_type, target_id, need=need)

    if scenario_type == "device_decommission":
        from app.models.device import Device
        dev = await session.get(Device, target_id)
        if dev is None:
            raise ScenarioError("impact_target_not_found", "Target not found", status=404)
        roots = await device_addresses(session, dev.id)
        return Scenario(scenario_type, target_type, dev.id, dev.name, dev.customer_id, roots,
                        device_id=dev.id, device_name=dev.name)

    root = await _addr_row(session, target_id)
    if root is None:
        raise ScenarioError("impact_target_not_found", "Target not found", status=404)
    sc = Scenario(scenario_type, target_type, root.ip_id, root.ip_text, root.customer_id, [root])
    await _validate_renumber(session, user, sc, root, parameters)
    return sc


async def _validate_renumber(session: AsyncSession, user: Any, sc: Scenario, root: TargetAddr,
                             parameters: dict[str, Any]) -> None:
    raw = str(parameters.get("new_ip") or "").strip()
    if not raw:
        raise ScenarioError("impact_invalid_target_address", "New IP is required", reason="missing")
    if "%" in raw:
        raise ScenarioError("impact_invalid_target_address", "Scoped addresses are not supported",
                            address=raw[:64], reason="scoped")
    try:
        new = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ScenarioError("impact_invalid_target_address", "Not an IP address", address=raw[:64],
                            reason="syntax") from exc
    if new.version != root.aip.version:
        # 跨 family 不是改址，是遷移方案（規格 §5.3）
        raise ScenarioError("impact_invalid_target_address", "IPv4/IPv6 cross-family change is not a renumber",
                            address=str(new), reason="cross_family")
    if new == root.aip:
        raise ScenarioError("impact_invalid_target_address", "New IP equals the current IP",
                            address=str(new), reason="same_as_old")

    from app.services.permission import visible_ids
    vis_subnets = await visible_ids(session, user=user, object_type="subnet")
    subnet_id_raw = parameters.get("target_subnet_id")
    if subnet_id_raw:
        try:
            sid = uuid.UUID(str(subnet_id_raw))
        except ValueError as exc:
            raise ScenarioError("impact_target_scope_mismatch", "Bad subnet id") from exc
        row = (await session.execute(text(
            "SELECT id, cidr::text AS cidr, vrf_id FROM subnets WHERE id = :id AND archived_at IS NULL"),
            {"id": sid})).first()
        if row is None or (vis_subnets is not None and row.id not in vis_subnets):
            raise ScenarioError("impact_target_scope_mismatch", "Target subnet not found", status=404)
        net = ipaddress.ip_network(row.cidr, strict=False)
        if new not in net:
            raise ScenarioError("impact_target_scope_mismatch", "New IP is outside the target subnet",
                                address=str(new), subnet=row.cidr)
    else:
        # 同一個 VRF（含都沒有 VRF）裡、包含新位址的子網路，取最小的一層
        rows = (await session.execute(text("""
            SELECT id, cidr::text AS cidr, vrf_id, masklen(cidr) AS ml FROM subnets
             WHERE archived_at IS NULL AND cidr >>= CAST(:ip AS inet)
               AND vrf_id IS NOT DISTINCT FROM :vrf
             ORDER BY masklen(cidr) DESC
        """), {"ip": str(new), "vrf": root.vrf_id})).all()
        rows = [r for r in rows if vis_subnets is None or r.id in vis_subnets]
        if not rows:
            raise ScenarioError("impact_target_scope_mismatch", "No managed subnet contains the new IP",
                                address=str(new))
        best = [r for r in rows if r.ml == rows[0].ml]
        if len(best) > 1:
            raise ScenarioError("impact_ambiguous_target", "Several overlapping subnets contain the new IP",
                                status=409, address=str(new), subnets=", ".join(r.cidr for r in best),
                                candidates=[str(r.id) for r in best])
        row = best[0]
        net = ipaddress.ip_network(row.cidr, strict=False)
    why = special_reason(new, net)
    if why:
        raise ScenarioError("impact_invalid_target_address", "This address cannot be assigned",
                            address=str(new), reason=why)
    sc.new_ip, sc.new_aip = str(new), new
    sc.target_subnet_id, sc.target_subnet_cidr, sc.target_vrf_id = row.id, row.cidr, row.vrf_id
    sc.cross_subnet = row.id != root.subnet_id


async def candidates_for_address(session: AsyncSession, user: Any, ip_text: str) -> list[dict[str, Any]]:
    """同一個位址有好幾筆（重疊網段）：列出使用者看得到的候選，給畫面選（規格 §3.1）。"""
    from app.models.address import IPAddress
    from app.services.permission import visible_ids
    try:
        a = ipaddress.ip_address(ip_text.strip())
    except ValueError as exc:
        raise ScenarioError("impact_invalid_target_address", "Not an IP address", address=ip_text[:64],
                            reason="syntax") from exc
    vis = await visible_ids(session, user=user, object_type="ip")
    rows = (await session.execute(select(IPAddress.id).where(IPAddress.ip == str(a)))).scalars().all()
    out = []
    for i in rows:
        if vis is not None and i not in vis:
            continue
        t = await _addr_row(session, i)
        if t is not None:
            out.append({"id": str(t.ip_id), "ip": t.ip_text, "subnet_id": str(t.subnet_id), "subnet": t.subnet_cidr,
                        "vrf_id": str(t.vrf_id) if t.vrf_id else None, "hostname": t.hostname})
    return out
