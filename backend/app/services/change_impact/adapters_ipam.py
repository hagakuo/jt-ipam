"""IPAM 這一側的證據：新位址的衝突、活動證據、jt-ipam 自己設定裡的引用、文字線索、裝置的實體關係。

都是 jt-ipam 自己的資料，逐物件權限（IP／子網路／裝置的可見性）；ARP 屬 LibreNMS 等整合 → 全域讀取。
"""

from __future__ import annotations

import ipaddress
import json
from datetime import timedelta
from typing import Any

from sqlalchemy import select, text

from app.services.change_impact.context import Ctx
from app.services.change_impact.matching import norm_ip, text_mentions
from app.services.change_impact.model import Evidence, Finding, TargetAddr

ACTIVITY_WINDOW = timedelta(days=7)
_SEEN_FIELDS = ("last_seen_scanner", "last_seen_librenms", "last_seen_arp", "last_seen_wazuh",
                "last_seen_zabbix", "last_seen_ocs")


async def compute_overlap(ctx: Ctx) -> None:
    """根位址是否也落在別的（未封存）子網路：整合沒設範圍時，比中的證據分不出是哪一邊的。"""
    for r in ctx.roots:
        n = (await ctx.session.execute(text("""
            SELECT count(*) FROM subnets WHERE archived_at IS NULL AND cidr >>= CAST(:ip AS inet) AND id <> :sid
        """), {"ip": r.ip_text, "sid": r.subnet_id})).scalar() or 0
        ctx.overlap[r.ip_id] = n > 0


# ─────────────────── 新位址（改址目標） ───────────────────

async def new_ip(ctx: Ctx) -> None:
    sc = ctx.scenario
    if not ctx.is_renumber or sc.new_aip is None:
        return
    root = ctx.roots[0]
    rows = (await ctx.session.execute(text("""
        SELECT a.id, host(a.ip) AS ip, a.subnet_id, s.cidr::text AS cidr, s.vrf_id, a.state, a.hostname,
               a.device_id, a.updated_at
          FROM ip_addresses a JOIN subnets s ON s.id = a.subnet_id
         WHERE a.ip = CAST(:ip AS inet) AND s.archived_at IS NULL
    """), {"ip": sc.new_ip})).all()
    hidden = False
    for r in rows:
        if not ctx.can_see("ip", r.id):
            hidden = True
            continue
        key = ctx.add(Evidence(
            key=f"ip_address:{r.id}", source_type="ipam", object_type="ip_address", object_id=r.id,
            label=f"{r.ip} ({r.cidr})", payload={"ip": r.ip, "subnet": r.cidr, "state": r.state,
                                                 "hostname": r.hostname},
            observed_at=r.updated_at, freshness="current", visibility=("ip", r.id)))
        if r.subnet_id == sc.target_subnet_id:
            rule = "ipam.new_ip_reserved" if r.state == "reserved" else "ipam.new_ip_assigned"
            ctx.find(Finding(rule, "ip_address", f"{r.ip} ({r.cidr})", [key], subject_id=r.id, match_kind="exact",
                             params={"address": r.ip, "state": r.state, "hostname": r.hostname or ""},
                             visibility=("ip", r.id)))
        elif r.vrf_id == sc.target_vrf_id:
            # 同一個 VRF 的重疊子網路有同一個位址：可能是同一台，也可能不是 —— 要人確認
            ctx.find(Finding("ipam.new_ip_overlap_record", "ip_address", f"{r.ip} ({r.cidr})", [key],
                             subject_id=r.id, match_kind="exact",
                             params={"address": r.ip, "subnet": r.cidr}, visibility=("ip", r.id)))
    if hidden:
        ctx.gap("ipam", "permission_limited", affected="ipam")

    cd = (await ctx.session.execute(text("""
        SELECT id, host(ip) AS ip, until, previous_hostname FROM ip_cooldowns
         WHERE subnet_id = :sid AND ip = CAST(:ip AS inet) AND cleared_at IS NULL AND until > :now
    """), {"sid": sc.target_subnet_id, "ip": sc.new_ip, "now": ctx.now})).first()
    if cd is not None and ctx.can_see("subnet", sc.target_subnet_id):
        key = ctx.add(Evidence(key=f"ip_cooldown:{cd.id}", source_type="ipam", object_type="ip_cooldown",
                               object_id=cd.id, label=cd.ip, payload={"until": cd.until.isoformat(),
                                                                      "previous_hostname": cd.previous_hostname},
                               freshness="current", visibility=("subnet", sc.target_subnet_id)))
        ctx.find(Finding("ipam.new_ip_cooldown", "ip_address", cd.ip, [key], subject_key=cd.ip, match_kind="exact",
                         params={"address": cd.ip, "until": cd.until.isoformat()},
                         visibility=("subnet", sc.target_subnet_id)))

    if sc.cross_subnet:
        gw = (await ctx.session.execute(text("SELECT host(gateway) FROM subnets WHERE id = :id"),
                                        {"id": sc.target_subnet_id})).scalar()
        key = ctx.add(Evidence(key=f"subnet:{sc.target_subnet_id}", source_type="ipam", object_type="subnet",
                               object_id=sc.target_subnet_id, label=sc.target_subnet_cidr or "",
                               payload={"cidr": sc.target_subnet_cidr, "gateway": gw}, freshness="current",
                               visibility=("subnet", sc.target_subnet_id)))
        # 跨子網路：VLAN、閘道、路由、ACL、DHCP、實體接入位置都要確認；沒有閘道資料就不猜
        for item in ("vlan", "gateway", "route", "acl", "dhcp", "physical_port"):
            ctx.find(Finding("network.cross_subnet", "subnet", sc.target_subnet_cidr or "", [key],
                             subject_id=sc.target_subnet_id, subject_key=item, match_kind=None,
                             params={"item": item, "from": root.subnet_cidr, "to": sc.target_subnet_cidr or "",
                                     "gateway": gw or ""},
                             visibility=("subnet", sc.target_subnet_id)))
        if not gw:
            ctx.gap("ipam", "gateway_unknown", subnet=sc.target_subnet_cidr or "", affected="cross_subnet")


async def new_ip_activity(ctx: Ctx) -> None:
    """新位址最近有沒有人在用：ARP（整合）、未納管目擊（掃描代理）。沒看到 ≠ 可以用（規格 T07）。"""
    sc = ctx.scenario
    if not ctx.is_renumber or sc.new_aip is None:
        return
    since = ctx.now - ACTIVITY_WINDOW
    um = (await ctx.session.execute(text("""
        SELECT id, host(ip) AS ip, mac, hostname, source, last_seen_at FROM unmanaged_sightings
         WHERE subnet_id = :sid AND ip = CAST(:ip AS inet) AND last_seen_at >= :since
    """), {"sid": sc.target_subnet_id, "ip": sc.new_ip, "since": since})).all()
    for r in um:
        if not ctx.can_see("subnet", sc.target_subnet_id):
            break
        key = ctx.add(Evidence(key=f"unmanaged_sighting:{r.id}", source_type="activity",
                               object_type="unmanaged_sighting", object_id=r.id, label=r.ip,
                               payload={"mac": r.mac, "hostname": r.hostname, "source": r.source},
                               observed_at=r.last_seen_at, freshness="current",
                               visibility=("subnet", sc.target_subnet_id)))
        ctx.find(Finding("activity.new_ip_seen", "address", r.ip, [key], subject_key=r.ip, match_kind="exact",
                         params={"address": r.ip, "source": r.source, "mac": r.mac or "",
                                 "last_seen": r.last_seen_at.isoformat()},
                         visibility=("subnet", sc.target_subnet_id)))
    if ctx.allowed("librenms"):
        # ARP 列沒有命名空間：LibreNMS 的列只有 VRF 文字；其他來源的列有 subnet_id 界定範圍
        rows = (await ctx.session.execute(text("""
            SELECT id, host(ip) AS ip, mac::text AS mac, source, subnet_id, instance_id, last_seen_at
              FROM arp_entries
             WHERE ip = CAST(:ip AS inet) AND last_seen_at >= :since
               AND (subnet_id IS NULL OR subnet_id = :sid)
             ORDER BY last_seen_at DESC LIMIT 20
        """), {"ip": sc.new_ip, "since": since, "sid": sc.target_subnet_id})).all()
        for r in rows:
            key = ctx.add(Evidence(key=f"arp_entry:{r.id}", source_type="librenms", object_type="arp_entry",
                                   object_id=r.id, label=f"{r.ip} → {r.mac}",
                                   payload={"mac": r.mac, "source": r.source}, observed_at=None,
                                   collected_at=r.last_seen_at, freshness="collected_only",
                                   visibility=("global", None)))
            ctx.find(Finding("activity.new_ip_seen", "address", r.ip, [key], subject_key=r.ip, match_kind="exact",
                             params={"address": r.ip, "source": r.source, "mac": r.mac or "",
                                     "last_seen": r.last_seen_at.isoformat()},
                             strength="corroborated" if r.subnet_id else "inferred"))
        if rows:
            ctx.gap("librenms", "arp_observed_time_unknown", affected="activity")


# ─────────────────── 舊位址／裝置位址的活動 ───────────────────

async def root_activity(ctx: Ctx) -> None:
    since = ctx.now - ACTIVITY_WINDOW
    for root in ctx.roots:
        row = (await ctx.session.execute(text(f"""
            SELECT {", ".join(_SEEN_FIELDS)}, effective_status, in_dhcp_lease FROM ip_addresses WHERE id = :id
        """), {"id": root.ip_id})).mappings().first()  # noqa: S608 -- 欄位名稱是本檔常數
        if row is None:
            continue
        seen = {f.removeprefix("last_seen_"): row[f] for f in _SEEN_FIELDS if row[f] and row[f] >= since}
        if not seen:
            continue
        newest = max(seen.values())
        key = ctx.add(Evidence(key=f"ip_activity:{root.ip_id}", source_type="activity", object_type="ip_address",
                               object_id=root.ip_id, label=root.ip_text,
                               payload={"seen_by": sorted(seen), "effective_status": row["effective_status"]},
                               observed_at=newest, freshness="current", visibility=("ip", root.ip_id)))
        rule = "activity.old_ip_active" if ctx.is_renumber else "device.recent_activity"
        ctx.find(Finding(rule, "ip_address", root.ip_text, [key], subject_id=root.ip_id, match_kind="exact",
                         params={"address": root.ip_text, "sources": ", ".join(sorted(seen)),
                                 "last_seen": newest.isoformat()},
                         visibility=("ip", root.ip_id)))


# ─────────────────── jt-ipam 自己設定裡的引用 ───────────────────

def _host_of(url: str | None) -> str | None:
    from urllib.parse import urlsplit
    if not url:
        return None
    try:
        h = urlsplit(url if "://" in url else f"//{url}").hostname
    except ValueError:
        return None
    return h


_INTEGRATION_URLS: tuple[tuple[str, str, str, str], ...] = (
    ("app.models.librenms", "LibreNMSInstance", "api_url", "librenms"),
    ("app.models.firewall", "OPNsenseFirewall", "api_url", "opnsense"),
    ("app.models.pfsense", "PfSenseFirewall", "api_url", "pfsense"),
    ("app.models.fortigate", "FortiGateFirewall", "api_url", "fortigate"),
    ("app.models.paloalto", "PaloAltoFirewall", "api_url", "paloalto"),
    ("app.models.mikrotik", "MikroTikRouter", "api_url", "mikrotik"),
    ("app.models.virt", "ProxmoxInstance", "api_url", "proxmox"),
    ("app.models.esxi", "ESXiInstance", "api_url", "esxi"),
    ("app.models.zabbix", "ZabbixInstance", "api_url", "zabbix"),
    ("app.models.wazuh", "WazuhInstance", "api_url", "wazuh"),
    ("app.models.dns", "DNSServer", "api_url", "dns_server"),
    ("app.models.dns", "DNSServer", "server_address", "dns_server"),
    ("app.models.dhcp_standalone", "KeaDhcpServer", "api_url", "kea_dhcp"),
    ("app.models.windows_dhcp", "WindowsDhcpServer", "host", "windows_dhcp"),
    ("app.models.ocs", "OcsServer", "base_url", "ocs"),
)


async def config_refs(ctx: Ctx) -> None:
    import importlib
    targets = {r.aip: r for r in ctx.roots}
    # 子網路的閘道與 DNS 伺服器（逐物件：子網路可見才列）
    for root in ctx.roots:
        for s in (await ctx.session.execute(text("""
            SELECT id, cidr::text AS cidr, host(gateway) AS gw, dns_servers FROM subnets
             WHERE archived_at IS NULL AND (gateway = CAST(:ip AS inet) OR dns_servers ILIKE :like)
        """), {"ip": root.ip_text, "like": f"%{root.ip_text}%"})).all():
            if not ctx.can_see("subnet", s.id):
                continue
            key = ctx.add(Evidence(key=f"subnet:{s.id}", source_type="config", object_type="subnet", object_id=s.id,
                                   label=s.cidr, payload={"gateway": s.gw, "dns_servers": s.dns_servers},
                                   freshness="current", visibility=("subnet", s.id)))
            if s.gw and norm_ip(s.gw) == root.aip:
                ctx.find(Finding("config.subnet_gateway", "subnet", s.cidr, [key], subject_id=s.id,
                                 match_kind="exact", params={"address": root.ip_text, "subnet": s.cidr},
                                 visibility=("subnet", s.id)))
            if root.aip in text_mentions(s.dns_servers or "", [root.aip]):
                ctx.find(Finding("config.subnet_dns_server", "subnet", s.cidr, [key], subject_id=s.id,
                                 match_kind="exact", params={"address": root.ip_text, "subnet": s.cidr},
                                 visibility=("subnet", s.id)))
        flag = (await ctx.session.execute(text("SELECT is_dhcp_server FROM ip_addresses WHERE id = :id"),
                                          {"id": root.ip_id})).scalar()
        if flag:
            key = ctx.add(Evidence(key=f"ip_dhcp_server:{root.ip_id}", source_type="config", object_type="ip_address",
                                   object_id=root.ip_id, label=root.ip_text, payload={"is_dhcp_server": True},
                                   freshness="current", visibility=("ip", root.ip_id)))
            ctx.find(Finding("config.dhcp_server_ip", "ip_address", root.ip_text, [key], subject_id=root.ip_id,
                             match_kind="exact", params={"address": root.ip_text}, visibility=("ip", root.ip_id)))

    # VPN 通道端點（全域）
    if ctx.global_read:
        from app.models.physical import VPNTunnel
        for t in (await ctx.session.execute(select(VPNTunnel))).scalars().all():
            for side, ep in (("a", t.a_endpoint), ("b", t.b_endpoint)):
                a = norm_ip(ep)
                if a in targets:
                    key = ctx.add(Evidence(key=f"vpn_tunnel:{t.id}", source_type="config", object_type="vpn_tunnel",
                                           object_id=t.id, label=t.name, payload={"side": side, "endpoint": ep,
                                                                                  "type": t.type, "status": t.status},
                                           freshness="current"))
                    ctx.find(Finding("config.vpn_endpoint", "vpn_tunnel", t.name, [key], subject_id=t.id,
                                     match_kind="exact", params={"address": str(a), "side": side}))
    else:
        ctx.gap("config", "permission_limited", affected="vpn_endpoint")

    # 跳板主機與各整合的連線端點：管理資料，只給管理員
    if not ctx.is_admin:
        ctx.gap("config", "permission_limited", affected="integration_endpoint")
        return
    from app.models.jump_host import JumpHost
    for j in (await ctx.session.execute(select(JumpHost))).scalars().all():
        a = norm_ip(j.host)
        if a in targets:
            key = ctx.add(Evidence(key=f"jump_host:{j.id}", source_type="config", object_type="jump_host",
                                   object_id=j.id, label=j.name, payload={"host": j.host, "port": j.port},
                                   freshness="current", visibility=("admin", None)))
            ctx.find(Finding("config.jump_host", "jump_host", j.name, [key], subject_id=j.id, match_kind="exact",
                             params={"address": str(a)}, visibility=("admin", None)))
    for mod, cls, attr, kind in _INTEGRATION_URLS:
        model = getattr(importlib.import_module(mod), cls, None)
        if model is None or not hasattr(model, attr):
            continue
        for row in (await ctx.session.execute(select(model))).scalars().all():
            a = norm_ip(_host_of(getattr(row, attr, None)))
            if a in targets:
                name = str(getattr(row, "name", kind))
                key = ctx.add(Evidence(key=f"integration:{kind}:{row.id}:{attr}", source_type="config",
                                       object_type="integration", object_id=row.id, label=f"{kind} {name}",
                                       payload={"kind": kind, "field": attr}, freshness="current",
                                       visibility=("admin", None)))
                ctx.find(Finding("config.integration_endpoint", "integration", f"{kind} {name}", [key],
                                 subject_id=row.id, subject_key=f"{kind}:{attr}", match_kind="exact",
                                 params={"address": str(a), "kind": kind, "field": attr},
                                 visibility=("admin", None)))


# ─────────────────── 文字線索 ───────────────────

async def text_hints(ctx: Ctx) -> None:
    """其他記錄的說明、備註、擁有者、自訂欄位裡出現這個位址：只是線索，需人工確認（規格 §5.3、T02）。

    以 token 邊界比對：198.51.100.2 不會比中寫著 198.51.100.20 的備註。
    """
    root_ids = {r.ip_id for r in ctx.roots}
    targets = [r.aip for r in ctx.roots]
    for root in ctx.roots:
        like = f"%{root.ip_text}%"
        for r in (await ctx.session.execute(text("""
            SELECT id, host(ip) AS ip, description, note, owner, custom_fields::text AS cf FROM ip_addresses
             WHERE description ILIKE :l OR note ILIKE :l OR owner ILIKE :l OR custom_fields::text ILIKE :l
             LIMIT 200
        """), {"l": like})).all():
            if r.id in root_ids or not ctx.can_see("ip", r.id):
                continue
            blob = " ".join(x for x in (r.description, r.note, r.owner, r.cf) if x)
            for a in text_mentions(blob, targets):
                _hint(ctx, "ip_address", r.id, r.ip, str(a), ("ip", r.id))
        for r in (await ctx.session.execute(text("""
            SELECT id, cidr::text AS cidr, description, custom_fields::text AS cf FROM subnets
             WHERE archived_at IS NULL AND (description ILIKE :l OR custom_fields::text ILIKE :l) LIMIT 200
        """), {"l": like})).all():
            if not ctx.can_see("subnet", r.id):
                continue
            for a in text_mentions(" ".join(x for x in (r.description, r.cf) if x), targets):
                _hint(ctx, "subnet", r.id, r.cidr, str(a), ("subnet", r.id))
        for r in (await ctx.session.execute(text("""
            SELECT id, name, description, custom_fields::text AS cf FROM devices
             WHERE description ILIKE :l OR custom_fields::text ILIKE :l LIMIT 200
        """), {"l": like})).all():
            if not ctx.can_see("device", r.id) or r.id == ctx.scenario.device_id:
                continue
            for a in text_mentions(" ".join(x for x in (r.description, r.cf) if x), targets):
                _hint(ctx, "device", r.id, r.name, str(a), ("device", r.id))


def _hint(ctx: Ctx, otype: str, oid: Any, label: str, addr: str, vis: tuple[str, Any]) -> None:
    key = ctx.add(Evidence(key=f"text:{otype}:{oid}", source_type="text", object_type=otype, object_id=oid,
                           label=label, payload={"mentions": addr}, freshness="current", visibility=vis))
    ctx.find(Finding("text.hint", otype, label, [key], subject_id=oid, match_kind="text_hint",
                     params={"address": addr}, visibility=vis))


# ─────────────────── 裝置除役：實體與關聯 ───────────────────

async def device_relations(ctx: Ctx) -> None:
    sc = ctx.scenario
    if sc.scenario_type != "device_decommission" or sc.device_id is None:
        return
    dev_id = sc.device_id
    vis = ("device", dev_id)
    if not ctx.roots:
        key = ctx.add(Evidence(key=f"device:{dev_id}", source_type="ipam", object_type="device", object_id=dev_id,
                               label=sc.device_name or "", payload={"ips": 0}, freshness="current", visibility=vis))
        ctx.find(Finding("device.no_ips", "device", sc.device_name or "", [key], subject_id=dev_id, visibility=vis))
    d = (await ctx.session.execute(text("""
        SELECT d.rack_id, r.name AS rack, d.u_position, d.u_size FROM devices d
          LEFT JOIN racks r ON r.id = d.rack_id WHERE d.id = :id
    """), {"id": dev_id})).first()
    if d is not None and d.rack_id:
        key = ctx.add(Evidence(key=f"device_rack:{dev_id}", source_type="physical", object_type="rack",
                               object_id=d.rack_id, label=d.rack or "", payload={"u_position": d.u_position,
                                                                                 "u_size": d.u_size},
                               freshness="current", visibility=vis))
        ctx.find(Finding("device.rack", "rack", d.rack or "", [key], subject_id=d.rack_id,
                         params={"u": d.u_position or "", "size": d.u_size or ""}, visibility=vis))
    if not ctx.global_read:
        # 佈線、電力、電路、VPN 都是全域資料
        ctx.gap("physical", "permission_limited", affected="physical")
        return
    cables = (await ctx.session.execute(text("""
        SELECT DISTINCT c.id, COALESCE(c.label, '') AS label, c.status FROM cables c
          JOIN cable_terminations t ON t.cable_id = c.id
         WHERE c.status <> 'decommissioned' AND (
               (t.object_type = 'device' AND t.object_id = :d)
            OR (t.object_type = 'device_port' AND t.object_id IN (SELECT id FROM device_ports WHERE device_id = :d)))
    """), {"d": dev_id})).all()
    for c in cables:
        key = ctx.add(Evidence(key=f"cable:{c.id}", source_type="physical", object_type="cable", object_id=c.id,
                               label=c.label or str(c.id)[:8], payload={"status": c.status}, freshness="current"))
        ctx.find(Finding("device.cables", "cable", c.label or str(c.id)[:8], [key], subject_id=c.id,
                         params={"status": c.status}))
    for p in (await ctx.session.execute(text("""
        SELECT pp.id, pp.name, o.label AS outlet FROM device_power_ports pp
          LEFT JOIN power_outlets o ON o.id = pp.outlet_id WHERE pp.device_id = :d
    """), {"d": dev_id})).all():
        key = ctx.add(Evidence(key=f"power_port:{p.id}", source_type="physical", object_type="device_power_port",
                               object_id=p.id, label=p.name, payload={"outlet": p.outlet}, freshness="current"))
        ctx.find(Finding("device.power", "device_power_port", p.name, [key], subject_id=p.id,
                         params={"outlet": p.outlet or ""}))
    for c in (await ctx.session.execute(text(
            "SELECT id, cid, status FROM circuits WHERE device_id = :d"), {"d": dev_id})).all():
        key = ctx.add(Evidence(key=f"circuit:{c.id}", source_type="physical", object_type="circuit", object_id=c.id,
                               label=c.cid, payload={"status": c.status}, freshness="current"))
        ctx.find(Finding("device.circuit", "circuit", c.cid, [key], subject_id=c.id, params={"status": c.status}))
    for t in (await ctx.session.execute(text("""
        SELECT id, name, status, a_device_id, b_device_id FROM vpn_tunnels WHERE a_device_id = :d OR b_device_id = :d
    """), {"d": dev_id})).all():
        key = ctx.add(Evidence(key=f"vpn_tunnel:{t.id}", source_type="config", object_type="vpn_tunnel",
                               object_id=t.id, label=t.name, payload={"status": t.status}, freshness="current"))
        ctx.find(Finding("device.vpn_tunnel", "vpn_tunnel", t.name, [key], subject_id=t.id,
                         params={"status": t.status}))


def json_dumps(o: Any) -> str:
    return json.dumps(o, ensure_ascii=False, default=str)


def subnet_of(root: TargetAddr) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(root.subnet_cidr, strict=False)
