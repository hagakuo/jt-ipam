"""整合這一側的證據：DNS、DHCP、防火牆與別名、NAT、監控、虛擬化、憑證。

共同原則：
- 整合有設範圍、但沒涵蓋根位址的子網路 → 那是別的命名空間，不算
- 整合沒設範圍、根位址又在重疊網段 → 證據降為「推定」並記缺口（`Ctx.strength_for`）
- 停用的規則、別名照樣列出，但只是參考（不會擋）
- 解析不了的語意（FQDN、URL、地理位置、反向比對、介面網段）記缺口，不假裝看過
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import select, text

from app.services.change_impact.context import Ctx
from app.services.change_impact.matching import (
    ANY_VALUES,
    covers_both,
    norm_ip,
    resolve_groups,
    value_match,
)
from app.services.change_impact.model import Evidence, Finding, TargetAddr

LEASE_WINDOW = timedelta(days=7)
_FAKE_TTL = frozenset({"unbound_opnsense", "univention_ucs"})
_CAST_INET = "CASE WHEN {c} ~ '^[0-9A-Fa-f:.]+$' THEN CAST({c} AS inet) END"


def _addresses(ctx: Ctx) -> list[TargetAddr]:
    return list(ctx.roots)


# ─────────────────── DNS ───────────────────

async def dns(ctx: Ctx) -> None:
    srcs = ctx.sources_of("dns")
    if not srcs or not ctx.allowed("dns"):
        return
    ctx.gap("dns", "dns_cname_not_collected", affected="dns")
    ctx.gap("dns", "dns_view_not_modeled", affected="dns")
    types = dict((await ctx.session.execute(text("SELECT id, type FROM dns_servers"))).all())
    by_id = {s.id: s for s in srcs}
    for root in _addresses(ctx):
        rows = (await ctx.session.execute(text(f"""
            SELECT r.id, r.name, r.type, r.value, r.ttl, r.source, r.last_seen_at, z.name AS zone, z.server_id
              FROM dns_records r JOIN dns_zones z ON z.id = r.zone_id
             WHERE r.type IN ('A', 'AAAA') AND {_CAST_INET.format(c="r.value")} = CAST(:ip AS inet)
        """), {"ip": root.ip_text})).all()  # noqa: S608 -- 片段是本檔常數
        rp = root.aip.reverse_pointer.lower()
        zones = (await ctx.session.execute(text("""
            SELECT id, name, server_id FROM dns_zones
             WHERE :rp = rtrim(lower(name), '.') OR :rp LIKE '%.' || rtrim(lower(name), '.')
        """), {"rp": rp})).all()
        ptr_rows = []
        for z in zones:
            zn = z.name.rstrip(".").lower()
            rel = rp[: -len(zn) - 1] if rp != zn else "@"
            ptr_rows += (await ctx.session.execute(text("""
                SELECT r.id, r.name, r.type, r.value, r.ttl, r.source, r.last_seen_at, CAST(:zn AS text) AS zone,
                       CAST(:sid AS uuid) AS server_id
                  FROM dns_records r WHERE r.zone_id = :zid AND r.type = 'PTR'
                   AND rtrim(lower(r.name), '.') IN (:rel, :full)
            """), {"zid": z.id, "zn": z.name, "sid": z.server_id, "rel": rel, "full": rp})).all()
        for r in [*rows, *ptr_rows]:
            src = by_id.get(r.server_id)
            if src is None or ctx.in_scope(src, root) is False:
                continue
            ttl_known = types.get(r.server_id) not in _FAKE_TTL
            if not ttl_known:
                ctx.gap("dns", "ttl_unknown", scope=src.ref, server=src.name)
            fqdn = r.name if r.name.endswith(".") or r.zone.rstrip(".") in r.name else f"{r.name}.{r.zone.rstrip('.')}"
            label = f"{fqdn} {r.type} {r.value}"
            key = ctx.add(Evidence(key=f"dns_record:{r.id}", source_type="dns", object_type="dns_record", object_id=r.id,
                                   integration_ref=src.ref, label=label[:300],
                                   payload={"name": fqdn, "type": r.type, "value": r.value, "ttl": r.ttl,
                                            "ttl_known": ttl_known, "zone": r.zone, "server": src.name,
                                            "origin": r.source},
                                   observed_at=r.last_seen_at, freshness=src.freshness))
            rule = "dns.ptr_record" if r.type == "PTR" else "dns.address_record"
            ctx.find(Finding(rule, "dns_record", label[:300], [key], subject_id=r.id, match_kind="exact",
                             params={"address": root.ip_text, "name": fqdn, "ttl": r.ttl if ttl_known else None,
                                     "server": src.name},
                             strength=ctx.strength_for(src, root)))


# ─────────────────── DHCP ───────────────────

async def dhcp(ctx: Ctx) -> None:
    srcs = ctx.sources_of("dhcp")
    if not srcs or not ctx.allowed("dhcp"):
        return
    ctx.gap("dhcp", "dhcp_lease_expiry_unknown", affected="dhcp")
    v6_kinds = {s.kind for s in srcs if "ipv4_only" in s.capabilities}
    sc = ctx.scenario
    if any(r.aip.version == 6 for r in ctx.roots) or (sc.new_aip is not None and sc.new_aip.version == 6):
        for k in sorted(v6_kinds):
            ctx.gap("dhcp", "source_ipv4_only", source=k, affected="dhcp")
    since = ctx.now - LEASE_WINDOW

    async def reservations(addr: str) -> list[Any]:
        return list((await ctx.session.execute(text(f"""
            SELECT id, ip, mac, hostname, source_type, source_id, source_name, synced_at FROM dhcp_reservations
             WHERE {_CAST_INET.format(c="ip")} = CAST(:ip AS inet)
        """), {"ip": addr})).all())  # noqa: S608

    async def pools(aip: Any) -> list[Any]:
        rows = (await ctx.session.execute(text(
            "SELECT id, start_ip, end_ip, source_type, source_id, source_name, family, synced_at FROM dhcp_pool_ranges"
        ))).all()
        return [r for r in rows if value_match(f"{r.start_ip}-{r.end_ip}", aip)]

    def ev_res(r: Any, root: TargetAddr | None) -> str:
        src = ctx.source(r.source_type, r.source_id)
        return ctx.add(Evidence(key=f"dhcp_reservation:{r.id}", source_type="dhcp", object_type="dhcp_reservation",
                                object_id=r.id, integration_ref=f"{r.source_type}:{r.source_id}",
                                label=f"{r.ip} {r.mac or ''} {r.hostname or ''}".strip(),
                                payload={"ip": r.ip, "mac": r.mac, "hostname": r.hostname,
                                         "source": r.source_name or r.source_type},
                                observed_at=r.synced_at, freshness=src.freshness if src else "unknown"))

    for root in _addresses(ctx):
        for r in await reservations(root.ip_text):
            src = ctx.source(r.source_type, r.source_id)
            if ctx.in_scope(src, root) is False:
                continue
            key = ev_res(r, root)
            ctx.find(Finding("dhcp.reservation", "dhcp_reservation", f"{r.ip} {r.mac or ''}".strip(), [key],
                             subject_id=r.id, match_kind="exact",
                             params={"address": root.ip_text, "mac": r.mac or "", "source": r.source_name or ""},
                             strength=ctx.strength_for(src, root)))
        for ls in (await ctx.session.execute(text("""
            SELECT id, source_type, source_id, first_seen_at, last_seen_at FROM dhcp_lease_sightings
             WHERE ip_address_id = :id AND last_seen_at >= :since
        """), {"id": root.ip_id, "since": since})).all():
            src = ctx.source(ls.source_type, ls.source_id)
            key = ctx.add(Evidence(key=f"dhcp_lease:{ls.id}", source_type="dhcp", object_type="dhcp_lease",
                                   object_id=ls.id, integration_ref=f"{ls.source_type}:{ls.source_id}",
                                   label=root.ip_text, payload={"source": src.name if src else ls.source_type,
                                                                "expiry_known": False},
                                   observed_at=ls.last_seen_at, freshness=src.freshness if src else "unknown"))
            ctx.find(Finding("dhcp.active_lease", "dhcp_lease", root.ip_text, [key], subject_id=ls.id,
                             match_kind="exact", params={"address": root.ip_text,
                                                         "last_seen": ls.last_seen_at.isoformat()}))
        for p in await pools(root.aip):
            src = ctx.source(p.source_type, p.source_id)
            if ctx.in_scope(src, root) is False:
                continue
            key = ctx.add(Evidence(key=f"dhcp_pool:{p.id}", source_type="dhcp", object_type="dhcp_pool", object_id=p.id,
                                   integration_ref=f"{p.source_type}:{p.source_id}", label=f"{p.start_ip}-{p.end_ip}",
                                   payload={"source": p.source_name or p.source_type}, observed_at=p.synced_at,
                                   freshness=src.freshness if src else "unknown"))
            ctx.find(Finding("dhcp.pool_member", "dhcp_pool", f"{p.start_ip}-{p.end_ip}", [key], subject_id=p.id,
                             match_kind="range_contains", params={"address": root.ip_text}))

    if not ctx.is_renumber or sc.new_aip is None:
        return
    root = ctx.roots[0]
    for r in await reservations(sc.new_ip or ""):
        src = ctx.source(r.source_type, r.source_id)
        key = ev_res(r, None)
        same = bool(r.mac and root.mac and r.mac.replace("-", ":").lower() == root.mac.lower())
        ctx.find(Finding("dhcp.new_ip_reserved_same_mac" if same else "dhcp.new_ip_reserved", "dhcp_reservation",
                         f"{r.ip} {r.mac or ''}".strip(), [key], subject_id=r.id, match_kind="exact",
                         params={"address": sc.new_ip, "mac": r.mac or "", "hostname": r.hostname or ""},
                         strength=ctx.strength_for(src, root)))
    new_objs = (await ctx.session.execute(text(
        "SELECT id FROM ip_addresses WHERE subnet_id = :sid AND ip = CAST(:ip AS inet)"),
        {"sid": sc.target_subnet_id, "ip": sc.new_ip})).scalars().all()
    if not new_objs:
        # 對不上 IP 物件的租約不會留下任何記錄：沒有物件就無法從租約判斷這個位址有沒有人用（缺口 G9）
        ctx.gap("dhcp", "dhcp_lease_unmatched_not_stored", address=sc.new_ip, affected="new_ip")
    for oid in new_objs:
        for ls in (await ctx.session.execute(text("""
            SELECT id, source_type, source_id, last_seen_at FROM dhcp_lease_sightings
             WHERE ip_address_id = :id AND last_seen_at >= :since
        """), {"id": oid, "since": since})).all():
            src = ctx.source(ls.source_type, ls.source_id)
            key = ctx.add(Evidence(key=f"dhcp_lease:{ls.id}", source_type="dhcp", object_type="dhcp_lease",
                                   object_id=ls.id, integration_ref=f"{ls.source_type}:{ls.source_id}",
                                   label=sc.new_ip or "", payload={"source": src.name if src else ls.source_type},
                                   observed_at=ls.last_seen_at, freshness=src.freshness if src else "unknown"))
            ctx.find(Finding("dhcp.new_ip_leased", "dhcp_lease", sc.new_ip or "", [key], subject_id=ls.id,
                             match_kind="exact", params={"address": sc.new_ip,
                                                         "last_seen": ls.last_seen_at.isoformat()}))
    for p in await pools(sc.new_aip):
        src = ctx.source(p.source_type, p.source_id)
        key = ctx.add(Evidence(key=f"dhcp_pool:{p.id}", source_type="dhcp", object_type="dhcp_pool", object_id=p.id,
                               integration_ref=f"{p.source_type}:{p.source_id}", label=f"{p.start_ip}-{p.end_ip}",
                               payload={"source": p.source_name or p.source_type}, observed_at=p.synced_at,
                               freshness=src.freshness if src else "unknown"))
        ctx.find(Finding("dhcp.new_ip_in_pool", "dhcp_pool", f"{p.start_ip}-{p.end_ip}", [key], subject_id=p.id,
                         match_kind="range_contains", params={"address": sc.new_ip}))


# ─────────────────── 防火牆 ───────────────────

class _FwScope:
    """一台防火牆（FortiGate 再分 VDOM、Palo Alto 分 vsys）的物件與規則，正規化成同一種形狀。

    物件名稱只在同一個範圍內有意義：兩台防火牆剛好有同名的別名，不可以混在一起（M0 缺口 G13）。
    """

    def __init__(self, vendor: str, fw_id: uuid.UUID, fw_name: str, partition: str | None = None) -> None:
        self.vendor, self.fw_id, self.fw_name, self.partition = vendor, fw_id, fw_name, partition
        self.groups: dict[str, list[str]] = {}
        self.objects: dict[str, dict[str, Any]] = {}      # name → {id, descr, enabled, type}
        self.rules: list[dict[str, Any]] = []
        self.dynamic_objects: int = 0
        self.iface_nets: bool = False

    @property
    def ref(self) -> str:
        return f"{self.vendor}:{self.fw_id}"

    @property
    def label(self) -> str:
        return f"{self.fw_name}/{self.partition}" if self.partition else self.fw_name


def _split_names(v: Any) -> list[str]:
    s = str(v or "").strip()
    if not s:
        return []
    return [p.strip() for p in s.split(",") if p.strip()]


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


_DYNAMIC_ALIAS = frozenset({"url", "urltable", "urltable_ports", "geoip", "asn", "dynipv6host", "external",
                            "authgroup", "mac", "internal"})


async def _load_firewalls(ctx: Ctx) -> list[_FwScope]:
    from app.models.firewall import OPNsenseFirewall, OPNsenseSyncedAlias
    from app.models.firewall_rule import OPNsenseRule
    from app.models.fortigate import FortiGateAddressObject, FortiGateFirewall, FortiGatePolicy
    from app.models.mikrotik import MikroTikAddressList, MikroTikRouter, MikroTikRule
    from app.models.paloalto import PaloAltoAddressObject, PaloAltoFirewall, PaloAltoPolicy
    from app.models.pfsense import PfSenseFirewall, PfSenseSyncedAlias

    enabled = {(s.kind, s.id) for s in ctx.sources_of("firewall")}
    scopes: dict[tuple[str, Any, str | None], _FwScope] = {}

    def scope(vendor: str, fw_id: Any, name: str, part: str | None = None) -> _FwScope:
        k = (vendor, fw_id, part)
        if k not in scopes:
            scopes[k] = _FwScope(vendor, fw_id, name, part)
        return scopes[k]

    s = ctx.session
    # OPNsense
    opn = {f.id: f.name for f in (await s.execute(select(OPNsenseFirewall))).scalars().all()
           if ("opnsense", f.id) in enabled}
    for a in (await s.execute(select(OPNsenseSyncedAlias))).scalars().all():
        if a.firewall_id not in opn:
            continue
        sc = scope("opnsense", a.firewall_id, opn[a.firewall_id])
        if (a.alias_type or "").lower() in _DYNAMIC_ALIAS:
            sc.dynamic_objects += 1
            continue
        if (a.alias_type or "").lower() == "port":
            continue
        sc.groups[a.name] = [str(x) for x in (a.content or [])]
        sc.objects[a.name] = {"id": a.id, "descr": (a.description or "")[:120], "enabled": a.enabled,
                              "type": a.alias_type, "members": len(a.content or [])}
    for r in (await s.execute(select(OPNsenseRule))).scalars().all():
        if r.firewall_id not in opn:
            continue
        raw = r.raw or {}
        scope("opnsense", r.firewall_id, opn[r.firewall_id]).rules.append({
            "id": r.id, "key": None, "label": (r.description or f"#{r.sequence or ''}")[:120],
            "src": [r.source_net] if r.source_net else [], "dst": [r.destination_net] if r.destination_net else [],
            "src_not": _truthy(raw.get("source_not")), "dst_not": _truthy(raw.get("destination_not")),
            "enabled": bool(r.enabled), "action": r.action, "interface": r.interface,
            "observed": r.last_synced_at})
    # pfSense
    pfs = {f.id: f for f in (await s.execute(select(PfSenseFirewall))).scalars().all() if ("pfsense", f.id) in enabled}
    for a in (await s.execute(select(PfSenseSyncedAlias))).scalars().all():
        if a.firewall_id not in pfs:
            continue
        sc = scope("pfsense", a.firewall_id, pfs[a.firewall_id].name)
        if (a.alias_type or "").lower() in _DYNAMIC_ALIAS:
            sc.dynamic_objects += 1
            continue
        if (a.alias_type or "").lower() == "port":
            continue
        sc.groups[a.name] = [str(x) for x in (a.members or [])]
        sc.objects[a.name] = {"id": a.id, "descr": (a.descr or "")[:120], "enabled": True, "type": a.alias_type,
                              "members": len(a.members or [])}
    for fw in pfs.values():
        sc = scope("pfsense", fw.id, fw.name)
        for pos, r in enumerate(fw.rules or []):
            if not isinstance(r, dict):
                continue

            def side(v: Any) -> tuple[list[str], bool]:
                if isinstance(v, dict):
                    vals = [str(v[k]) for k in ("address", "network") if v.get(k) not in (None, "")]
                    return vals, "not" in v
                return ([str(v)] if v not in (None, "") else []), False
            sv, sn = side(r.get("source"))
            dv, dn = side(r.get("destination"))
            sc.rules.append({"id": None, "key": str(r.get("tracker") or f"#{pos}"),
                             "label": str(r.get("descr") or f"#{pos}")[:120], "src": sv, "dst": dv,
                             "src_not": sn, "dst_not": dn, "enabled": not r.get("disabled"),
                             "action": r.get("type"), "interface": r.get("interface"), "observed": None})
    # FortiGate（物件與政策都以 VDOM 為範圍）
    fgs = {f.id: f.name for f in (await s.execute(select(FortiGateFirewall))).scalars().all()
           if ("fortigate", f.id) in enabled}
    for o in (await s.execute(select(FortiGateAddressObject))).scalars().all():
        if o.firewall_id not in fgs:
            continue
        sc = scope("fortigate", o.firewall_id, fgs[o.firewall_id], o.vdom)
        members = [str(x) for x in (o.members or [])] if o.kind == "group" else ([str(o.value)] if o.value else [])
        if o.kind != "group" and o.value and norm_ip(o.value) is None and not _is_net(o.value):
            sc.dynamic_objects += 1
        sc.groups[o.name] = members
        sc.objects[o.name] = {"id": o.id, "descr": (o.comment or "")[:120], "enabled": True, "type": o.kind,
                              "members": len(members)}
    for p in (await s.execute(select(FortiGatePolicy))).scalars().all():
        if p.firewall_id not in fgs:
            continue
        raw = p.raw or {}
        scope("fortigate", p.firewall_id, fgs[p.firewall_id], p.vdom).rules.append({
            "id": p.id, "key": None, "label": (p.name or f"policy {p.policyid}")[:120],
            "src": _split_names(p.srcaddr), "dst": _split_names(p.dstaddr),
            "src_not": str(raw.get("srcaddr-negate", "")).lower() == "enable",
            "dst_not": str(raw.get("dstaddr-negate", "")).lower() == "enable",
            "enabled": (p.status or "enable") != "disable", "action": p.action,
            "interface": f"{p.srcintf or ''}->{p.dstintf or ''}", "observed": p.last_sync_at})
    # Palo Alto（以 vsys 為範圍）
    pas = {f.id: f.name for f in (await s.execute(select(PaloAltoFirewall))).scalars().all()
           if ("paloalto", f.id) in enabled}
    for o in (await s.execute(select(PaloAltoAddressObject))).scalars().all():
        if o.firewall_id not in pas:
            continue
        sc = scope("paloalto", o.firewall_id, pas[o.firewall_id], o.vsys)
        members = [str(x) for x in (o.members or [])] if o.kind == "group" else ([str(o.value)] if o.value else [])
        if o.kind != "group" and o.value and norm_ip(o.value) is None and not _is_net(o.value):
            sc.dynamic_objects += 1
        sc.groups[o.name] = members
        sc.objects[o.name] = {"id": o.id, "descr": (o.description or "")[:120], "enabled": True, "type": o.kind,
                              "members": len(members)}
    for p in (await s.execute(select(PaloAltoPolicy))).scalars().all():
        if p.firewall_id not in pas:
            continue
        raw = p.raw or {}
        scope("paloalto", p.firewall_id, pas[p.firewall_id], p.vsys).rules.append({
            "id": p.id, "key": None, "label": p.name[:120], "src": _split_names(p.source),
            "dst": _split_names(p.destination),
            "src_not": str(raw.get("negate-source", "")).lower() == "yes",
            "dst_not": str(raw.get("negate-destination", "")).lower() == "yes",
            "enabled": not p.disabled, "action": p.action,
            "interface": f"{p.from_zone or ''}->{p.to_zone or ''}", "observed": p.last_sync_at})
    # MikroTik（address-list 一列一個成員）
    mts = {f.id: f.name for f in (await s.execute(select(MikroTikRouter))).scalars().all()
           if ("mikrotik", f.id) in enabled}
    for e in (await s.execute(select(MikroTikAddressList))).scalars().all():
        if e.router_id not in mts:
            continue
        sc = scope("mikrotik", e.router_id, mts[e.router_id])
        sc.groups.setdefault(e.list_name, []).append(e.address)
        meta = sc.objects.setdefault(e.list_name, {"id": None, "descr": "", "enabled": True, "type": "address-list",
                                                   "members": 0})
        meta["members"] += 1
    for r in (await s.execute(select(MikroTikRule).where(MikroTikRule.table_name != "mangle"))).scalars().all():
        if r.router_id not in mts:
            continue

        def mt(v: str | None) -> tuple[list[str], bool]:
            t = (v or "").strip()
            neg = t.startswith("!")
            t = t.lstrip("!").removeprefix("list:")
            return ([t] if t else []), neg
        sv, sn = mt(r.src_address)
        dv, dn = mt(r.dst_address)
        if r.table_name == "nat" and r.to_addresses:
            dv = [*dv, r.to_addresses]
        scope("mikrotik", r.router_id, mts[r.router_id]).rules.append({
            "id": r.id, "key": None, "label": f"[{r.table_name}/{r.chain or ''}] {r.comment or ''}"[:120],
            "src": sv, "dst": dv, "src_not": sn, "dst_not": dn, "enabled": not r.disabled, "action": r.action,
            "interface": f"{r.in_interface or ''}->{r.out_interface or ''}", "observed": r.synced_at})
    return list(scopes.values())




def _is_net(v: str) -> bool:
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        return "-" in v and all(norm_ip(x) for x in v.split("-", 1))


async def firewall(ctx: Ctx) -> None:
    if not ctx.sources_of("firewall") or not ctx.allowed("firewall"):
        return
    depth = int(ctx.limits.get("group_depth", 16))
    scopes = await _load_firewalls(ctx)
    ctx.gap("firewall", "any_rules_not_listed", affected="firewall")
    pve_fw = (await ctx.session.execute(text(
        "SELECT count(*) FROM proxmox_instances WHERE enabled AND sync_firewall"))).scalar() or 0
    if pve_fw:
        ctx.gap("firewall", "pve_firewall_unsupported", affected="firewall")
    new = ctx.scenario.new_aip
    for sc in scopes:
        await ctx.check("firewall")
        src = ctx.source(sc.vendor, sc.fw_id)
        if sc.dynamic_objects:
            ctx.gap("firewall", "unknown_semantics", scope=sc.ref, firewall=sc.label, count=sc.dynamic_objects,
                    kind="dynamic_objects")
        for root in _addresses(ctx):
            if ctx.in_scope(src, root) is False:
                continue
            strength = ctx.strength_for(src, root)
            res = resolve_groups(sc.groups, root.aip, depth=depth)
            for cyc in res.cycles:
                ctx.gap("firewall", "fw_object_cycle", scope=sc.ref, firewall=sc.label, path=" → ".join(cyc))
            for name in sorted(res.depth_exceeded):
                ctx.gap("firewall", "fw_depth_exceeded", scope=sc.ref, firewall=sc.label, object=name, depth=depth)
            for gname, members in sorted(res.unknown_members.items()):
                ctx.gap("firewall", "unknown_semantics", scope=sc.ref, firewall=sc.label, object=gname,
                        kind="non_address_members", sample=", ".join(members[:3]))
            # 物件／別名本身：這個位址是成員（直接或經由子群組）
            for gname, hit in sorted(res.hits.items()):
                meta = sc.objects.get(gname, {})
                key = ctx.add(Evidence(
                    key=f"fw_object:{sc.ref}:{sc.partition or ''}:{gname}", source_type="firewall",
                    object_type="fw_object", object_id=meta.get("id"), object_key=gname, integration_ref=sc.ref,
                    label=f"{sc.label} {gname}"[:300],
                    payload={"firewall": sc.label, "vendor": sc.vendor, "object": gname, "path": hit.path,
                             "member": hit.member, "members": meta.get("members"), "type": meta.get("type"),
                             "enabled": meta.get("enabled", True), "descr": meta.get("descr", "")},
                    freshness=src.freshness if src else "unknown"))
                rule = _object_rule(ctx, hit.kind, hit.member, root.aip, new, meta)
                ctx.find(Finding(rule, "fw_object", f"{sc.label} {gname}"[:300], [key], subject_id=meta.get("id"),
                                 subject_key=f"{sc.ref}:{sc.partition or ''}:{gname}", match_kind=hit.kind,
                                 params={"address": root.ip_text, "object": gname, "firewall": sc.label,
                                         "members": meta.get("members") or 0, "path": " → ".join(hit.path)},
                                 path=[{"ref": f"fw_object:{p}", "label": p} for p in hit.path[:-1]],
                                 strength=strength))
            # 規則：值直接比中，或經由比中的物件
            for r in sc.rules:
                matched = None
                for side in ("src", "dst"):
                    for v in r[side]:
                        vs = str(v).strip()
                        if not vs or vs.lower() in ANY_VALUES:
                            continue
                        if vs in res.hits:
                            h = res.hits[vs]
                            matched = (side, "group_member" if h.kind == "exact" else h.kind, vs, h, r[f"{side}_not"])
                        else:
                            k = value_match(vs, root.aip)
                            if k:
                                matched = (side, k, vs, None, r[f"{side}_not"])
                            elif vs not in sc.groups and norm_ip(vs) is None and not _is_net(vs):
                                sc.iface_nets = True
                        if matched:
                            break
                    if matched:
                        break
                if not matched:
                    continue
                side, kind, value, hit, negated = matched
                rkey = str(r["id"]) if r["id"] else f"{sc.ref}:{r['key']}"
                key = ctx.add(Evidence(
                    key=f"fw_rule:{rkey}", source_type="firewall", object_type="fw_rule", object_id=r["id"],
                    object_key=r["key"], integration_ref=sc.ref, label=f"{sc.label} {r['label']}"[:300],
                    payload={"firewall": sc.label, "vendor": sc.vendor, "rule": r["label"], "side": side,
                             "value": value, "action": r["action"], "interface": r["interface"],
                             "enabled": r["enabled"], "negated": negated,
                             "via": hit.path if hit else None},
                    observed_at=r["observed"], freshness=src.freshness if src else "unknown"))
                if negated:
                    rule = "fw.rule_negated"
                elif not r["enabled"]:
                    rule = "fw.rule_disabled"
                elif kind in ("exact",):
                    rule = "fw.rule_exact"
                elif kind == "group_member":
                    rule = "fw.rule_group"
                elif new is not None and covers_both(hit.member if hit else value, root.aip, new):
                    rule = "fw.rule_range_both"
                else:
                    rule = "fw.rule_range"
                ctx.find(Finding(rule, "fw_rule", f"{sc.label} {r['label']}"[:300], [key], subject_id=r["id"],
                                 subject_key=rkey, match_kind=kind,
                                 params={"address": root.ip_text, "side": side, "value": value, "firewall": sc.label,
                                         "action": r["action"] or ""},
                                 path=[{"ref": f"fw_object:{p}", "label": p} for p in (hit.path[:-1] if hit else [])],
                                 strength=strength))
        if sc.iface_nets:
            ctx.gap("firewall", "interface_network_not_evaluated", scope=sc.ref, firewall=sc.label)


def _object_rule(ctx: Ctx, kind: str, member: str, old: Any, new: Any, meta: dict[str, Any]) -> str:
    if kind in ("cidr_contains", "range_contains"):
        return "fw.rule_range_both" if new is not None and covers_both(member, old, new) else "fw.rule_range"
    # 除役：別名還有別的成員 ＝共用，不可以整個刪掉，只能移除這個成員（規格 T13）
    if not ctx.is_renumber and int(meta.get("members") or 0) > 1:
        return "fw.object_shared"
    return "fw.object_member"


# ─────────────────── NAT ───────────────────

async def nat(ctx: Ctx) -> None:
    if not ctx.sources_of("nat") and not await _has_manual_nat(ctx):
        return
    if not ctx.allowed("nat"):
        return
    if ctx.sources_of("nat"):
        ctx.gap("nat", "nat_unresolved_address_not_stored", affected="nat")
    ids = [r.ip_id for r in ctx.roots]
    by_id = {r.ip_id: r for r in ctx.roots}
    rows = (await ctx.session.execute(text("""
        SELECT id, name, type, src_ip_id, dst_ip_id, disabled, source_origin, protocol, dst_port, device_id
          FROM nat_translations WHERE src_ip_id = ANY(:ids) OR dst_ip_id = ANY(:ids)
    """), {"ids": ids})).all() if ids else []
    for n in rows:
        root = by_id.get(n.dst_ip_id) or by_id.get(n.src_ip_id)
        side = "dst" if n.dst_ip_id in by_id else "src"
        key = ctx.add(Evidence(key=f"nat:{n.id}", source_type="nat", object_type="nat_translation", object_id=n.id,
                               integration_ref=n.source_origin, label=n.name[:300],
                               payload={"type": n.type, "side": side, "protocol": n.protocol, "dst_port": n.dst_port,
                                        "disabled": n.disabled, "origin": (n.source_origin or "manual").split(":")[0]},
                               freshness="current" if not n.source_origin else _origin_freshness(ctx, n.source_origin)))
        ctx.find(Finding("nat.translation_disabled" if n.disabled else "nat.translation", "nat_translation",
                         n.name[:300], [key], subject_id=n.id, match_kind="exact",
                         params={"address": root.ip_text if root else "", "side": side, "type": n.type}))
    if ctx.scenario.device_id:
        for n in (await ctx.session.execute(text(
                "SELECT id, name, type, disabled FROM nat_translations WHERE device_id = :d"),
                {"d": ctx.scenario.device_id})).all():
            key = ctx.add(Evidence(key=f"nat:{n.id}", source_type="nat", object_type="nat_translation",
                                   object_id=n.id, label=n.name[:300], payload={"type": n.type, "disabled": n.disabled},
                                   freshness="current"))
            ctx.find(Finding("device.nat_device", "nat_translation", n.name[:300], [key], subject_id=n.id,
                             params={"type": n.type}))


async def _has_manual_nat(ctx: Ctx) -> bool:
    return bool((await ctx.session.execute(text(
        "SELECT 1 FROM nat_translations WHERE source_origin IS NULL LIMIT 1"))).first())


def _origin_freshness(ctx: Ctx, origin: str) -> str:
    kind, _, sid = origin.partition(":")
    try:
        return ctx.freshness_of(kind, uuid.UUID(sid))
    except ValueError:
        return "unknown"


# ─────────────────── 監控與資產 ───────────────────

async def monitoring(ctx: Ctx) -> None:
    ids = [r.ip_id for r in ctx.roots]
    texts = [r.ip_text for r in ctx.roots]
    by_text = {r.ip_text: r for r in ctx.roots}
    by_id = {r.ip_id: r for r in ctx.roots}
    # Zabbix 與 LibreNMS 的清單是全域讀取（比照各自的唯讀頁面）
    if ctx.global_read:
        for h in (await ctx.session.execute(text("""
            SELECT h.id, h.host, h.name, host(h.ip) AS ip, h.jt_ipam_address_id, h.instance_id, h.synced_at
              FROM zabbix_hosts h WHERE h.jt_ipam_address_id = ANY(:ids) OR host(h.ip) = ANY(:texts)
        """), {"ids": ids, "texts": texts})).all():
            root = by_id.get(h.jt_ipam_address_id) or by_text.get(h.ip)
            if root is None:
                continue
            src = ctx.source("zabbix", h.instance_id)
            if ctx.in_scope(src, root) is False:
                continue
            key = ctx.add(Evidence(key=f"zabbix_host:{h.id}", source_type="monitoring", object_type="zabbix_host",
                                   object_id=h.id, integration_ref=f"zabbix:{h.instance_id}",
                                   label=(h.name or h.host)[:300], payload={"host": h.host, "ip": h.ip},
                                   observed_at=h.synced_at, freshness=src.freshness if src else "unknown"))
            ctx.find(Finding("monitoring.zabbix_host", "zabbix_host", (h.name or h.host)[:300], [key],
                             subject_id=h.id, match_kind="exact", params={"address": root.ip_text},
                             strength=ctx.strength_for(src, root)))
        dev = ctx.scenario.device_id
        for d in (await ctx.session.execute(text("""
            SELECT id, hostname, sysname, host(primary_ip) AS ip, instance_id, jt_ipam_device_id, last_seen_at
              FROM librenms_devices WHERE host(primary_ip) = ANY(:texts) OR (jt_ipam_device_id = :dev)
        """), {"texts": texts, "dev": dev})).all():
            root = by_text.get(d.ip)
            src = ctx.source("librenms", d.instance_id)
            if root is not None and ctx.in_scope(src, root) is False:
                continue
            label = (d.sysname or d.hostname or d.ip or "")[:300]
            key = ctx.add(Evidence(key=f"librenms_device:{d.id}", source_type="librenms",
                                   object_type="librenms_device", object_id=d.id,
                                   integration_ref=f"librenms:{d.instance_id}", label=label,
                                   payload={"primary_ip": d.ip, "linked_device": bool(d.jt_ipam_device_id)},
                                   observed_at=d.last_seen_at, freshness=src.freshness if src else "unknown"))
            ctx.find(Finding("monitoring.librenms_device", "librenms_device", label, [key], subject_id=d.id,
                             match_kind="exact" if root else None,
                             params={"address": root.ip_text if root else ""},
                             strength=ctx.strength_for(src, root) if root else None))
    elif ctx.sources_of("monitoring"):
        ctx.gap("monitoring", "permission_limited", affected="monitoring_global")
    # Wazuh、OCS、RustDesk：管理員才看得到
    if not ctx.allowed("monitoring"):
        return
    for a in (await ctx.session.execute(text("""
        SELECT id, name, host(ip) AS ip, jt_ipam_address_id, instance_id, status, last_keep_alive FROM wazuh_agents
         WHERE jt_ipam_address_id = ANY(:ids) OR host(ip) = ANY(:texts)
    """), {"ids": ids, "texts": texts})).all():
        root = by_id.get(a.jt_ipam_address_id) or by_text.get(a.ip)
        if root is None:
            continue
        src = ctx.source("wazuh", a.instance_id)
        key = ctx.add(Evidence(key=f"wazuh_agent:{a.id}", source_type="monitoring", object_type="wazuh_agent",
                               object_id=a.id, integration_ref=f"wazuh:{a.instance_id}", label=(a.name or a.ip)[:300],
                               payload={"status": a.status}, observed_at=a.last_keep_alive,
                               freshness=src.freshness if src else "unknown", visibility=("admin", None)))
        ctx.find(Finding("monitoring.wazuh_agent", "wazuh_agent", (a.name or a.ip)[:300], [key], subject_id=a.id,
                         match_kind="exact", params={"address": root.ip_text}, visibility=("admin", None)))
    for root in ctx.roots:
        o = (await ctx.session.execute(text(
            "SELECT ocs_id, ocs_tag, last_seen_ocs FROM ip_addresses WHERE id = :id AND ocs_id IS NOT NULL"),
            {"id": root.ip_id})).first()
        if o is not None:
            key = ctx.add(Evidence(key=f"ocs:{root.ip_id}", source_type="monitoring", object_type="ocs_computer",
                                   object_key=str(o.ocs_id), label=f"OCS #{o.ocs_id}", payload={"tag": o.ocs_tag},
                                   observed_at=o.last_seen_ocs, freshness="unknown", visibility=("admin", None)))
            ctx.find(Finding("monitoring.ocs_inventory", "ocs_computer", f"OCS #{o.ocs_id}", [key],
                             subject_key=str(o.ocs_id), params={"address": root.ip_text}, visibility=("admin", None)))
    for p in (await ctx.session.execute(text("""
        SELECT id, rustdesk_id, hostname, address_id, last_online_at FROM rustdesk_peers WHERE address_id = ANY(:ids)
    """), {"ids": ids})).all():
        root = by_id[p.address_id]
        key = ctx.add(Evidence(key=f"rustdesk_peer:{p.id}", source_type="monitoring", object_type="rustdesk_peer",
                               object_id=p.id, label=f"RustDesk {p.rustdesk_id}", payload={"hostname": p.hostname},
                               observed_at=p.last_online_at, freshness="unknown", visibility=("admin", None)))
        ctx.find(Finding("monitoring.rustdesk_peer", "rustdesk_peer", f"RustDesk {p.rustdesk_id}", [key],
                         subject_id=p.id, params={"address": root.ip_text}, visibility=("admin", None)))


# ─────────────────── 虛擬化 ───────────────────

async def virt(ctx: Ctx) -> None:
    if not ctx.sources_of("virt") or not ctx.allowed("virt"):
        return
    ids = [r.ip_id for r in ctx.roots]
    texts = [r.ip_text for r in ctx.roots]
    by_text = {r.ip_text: r for r in ctx.roots}
    by_id = {r.ip_id: r for r in ctx.roots}
    rows = (await ctx.session.execute(text("""
        SELECT vm.id AS vm_id, vm.name, vm.status, vm.kind, vm.node, vm.primary_ip_id, i.id AS if_id, i.name AS ifname,
               host(i.primary_ip) AS ip, i.mac::text AS mac, c.name AS cluster
          FROM virtual_machines vm JOIN virt_clusters c ON c.id = vm.cluster_id
          LEFT JOIN vm_interfaces i ON i.vm_id = vm.id
         WHERE vm.primary_ip_id = ANY(:ids) OR host(i.primary_ip) = ANY(:texts)
    """), {"ids": ids, "texts": texts})).all() if ids else []
    seen: set[Any] = set()
    for r in rows:
        if r.vm_id in seen:
            continue
        root = by_id.get(r.primary_ip_id) or by_text.get(r.ip)
        if root is None:
            continue
        seen.add(r.vm_id)
        explicit = r.primary_ip_id in by_id
        # 網卡 MAC 跟 IP 記錄的 MAC 對得上才算明確；只有位址對上可能是重疊網段的另一台
        mac_ok = bool(r.mac and root.mac and r.mac.lower() == root.mac.lower())
        key = ctx.add(Evidence(key=f"vm:{r.vm_id}", source_type="virt", object_type="virtual_machine",
                               object_id=r.vm_id, label=f"{r.cluster}/{r.name}"[:300],
                               payload={"status": r.status, "kind": r.kind, "node": r.node, "interface": r.ifname,
                                        "mac_match": mac_ok}, freshness="unknown"))
        ctx.find(Finding("virt.vm_interface", "virtual_machine", f"{r.cluster}/{r.name}"[:300], [key],
                         subject_id=r.vm_id, match_kind="exact",
                         params={"address": root.ip_text, "status": r.status, "node": r.node or ""},
                         strength="explicit" if explicit or mac_ok else "inferred"))
    sc = ctx.scenario
    if sc.scenario_type != "device_decommission" or sc.device_id is None:
        return
    dev = (await ctx.session.execute(text("SELECT name, fqdn FROM devices WHERE id = :d"),
                                     {"d": sc.device_id})).first()
    names = {n.lower() for n in (dev.name if dev else "", (dev.fqdn or "").split(".")[0] if dev else "") if n}
    vms = (await ctx.session.execute(text("""
        SELECT vm.id, vm.name, vm.status, vm.kind, vm.node, vm.device_id, vm.is_template, c.name AS cluster
          FROM virtual_machines vm JOIN virt_clusters c ON c.id = vm.cluster_id
         WHERE vm.device_id = :d OR lower(vm.node) = ANY(:names)
    """), {"d": sc.device_id, "names": list(names)})).all()
    running, stopped = [], []
    for v in vms:
        if v.device_id == sc.device_id:
            key = ctx.add(Evidence(key=f"vm:{v.id}", source_type="virt", object_type="virtual_machine",
                                   object_id=v.id, label=f"{v.cluster}/{v.name}"[:300],
                                   payload={"status": v.status, "kind": v.kind, "node": v.node}, freshness="unknown"))
            ctx.find(Finding("device.is_vm", "virtual_machine", f"{v.cluster}/{v.name}"[:300], [key],
                             subject_id=v.id, params={"status": v.status, "node": v.node or ""}))
            continue
        if v.is_template:
            continue
        (running if v.status == "running" else stopped).append(v)
    for group, rule in ((running, "device.hosts_running_workloads"), (stopped, "device.hosts_stopped_workloads")):
        for v in group:
            # 節點名稱對到裝置名稱是推定（VM 只記節點名稱文字，沒有外鍵：M0 缺口 G22）
            key = ctx.add(Evidence(key=f"vm:{v.id}", source_type="virt", object_type="virtual_machine",
                                   object_id=v.id, label=f"{v.cluster}/{v.name}"[:300],
                                   payload={"status": v.status, "kind": v.kind, "node": v.node}, freshness="unknown"))
            ctx.find(Finding(rule, "virtual_machine", f"{v.cluster}/{v.name}"[:300], [key], subject_id=v.id,
                             params={"status": v.status, "node": v.node or ""}))
    if running or stopped:
        ctx.gap("virt", "virt_ha_not_modeled", affected="workloads")


# ─────────────────── 憑證 ───────────────────

async def certs(ctx: Ctx) -> None:
    if not ctx.allowed("cert"):
        return
    from cryptography import x509

    targets = {r.aip: r for r in ctx.roots}
    names: dict[str, TargetAddr] = {}
    for r in ctx.roots:
        if r.hostname:
            names[r.hostname.lower().rstrip(".")] = r
            names[r.hostname.lower().split(".")[0]] = r
    # 只讀憑證本體（cert_pem），不碰私鑰欄（規格 T12）
    rows = (await ctx.session.execute(text("""
        SELECT v.id, v.certificate_id, c.name, v.cert_pem, v.not_after FROM cert_versions v
          JOIN certificates c ON c.id = v.certificate_id WHERE v.is_current
    """))).all()
    for v in rows:
        try:
            cert = x509.load_pem_x509_certificate(v.cert_pem.encode())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except (ValueError, x509.ExtensionNotFound):    # 解析不了、或沒有 SAN 的憑證不會引用這個位址
            continue
        ips = {ipaddress.ip_address(x) for x in san.get_values_for_type(x509.IPAddress)}
        dns_names = [str(x).lower().rstrip(".") for x in san.get_values_for_type(x509.DNSName)]
        hit_ips = [a for a in ips if a in targets]
        hit_names = [n for n in dns_names if n in names or n.split(".")[0] in names]
        if not hit_ips and not hit_names:
            continue
        key = ctx.add(Evidence(key=f"certificate:{v.certificate_id}", source_type="cert", object_type="certificate",
                               object_id=v.certificate_id, label=v.name,
                               payload={"ip_sans": sorted(str(a) for a in hit_ips), "dns_sans": hit_names[:10],
                                        "not_after": v.not_after.isoformat() if v.not_after else None},
                               freshness="current", visibility=("admin", None)))
        if hit_ips:
            for a in hit_ips:
                ctx.find(Finding("cert.ip_san", "certificate", v.name, [key], subject_id=v.certificate_id,
                                 match_kind="exact", params={"address": str(a)}, visibility=("admin", None)))
        else:
            # 憑證只寫 DNS 名稱：改 IP 不必重簽（規格 T12）
            ctx.find(Finding("cert.dns_san_only", "certificate", v.name, [key], subject_id=v.certificate_id,
                             params={"name": hit_names[0]}, visibility=("admin", None)))
    sc = ctx.scenario
    if sc.device_id:
        for a in (await ctx.session.execute(text(
                "SELECT id, name, scope_cert_ids, last_seen_at FROM cert_agents WHERE device_id = :d"),
                {"d": sc.device_id})).all():
            key = ctx.add(Evidence(key=f"cert_agent:{a.id}", source_type="cert", object_type="cert_agent",
                                   object_id=a.id, label=a.name,
                                   payload={"certificates": len(a.scope_cert_ids or [])},
                                   observed_at=a.last_seen_at, freshness="current", visibility=("admin", None)))
            ctx.find(Finding("device.cert_agent", "cert_agent", a.name, [key], subject_id=a.id,
                             params={"certificates": len(a.scope_cert_ids or [])}, visibility=("admin", None)))
