"""超大規模環境的虛構資料（GitHub issue #47 之後：超大規模要列入考量）。

開發與測試資料都是中等規模，於是「一次查詢放得下」「全部載進記憶體也還好」這類假設一直沒被
戳破，直到客戶站台踩到（單台裝置三萬多個埠 → IN 超過參數上限）。這支灌出一個大型站台，
給 tests/scale_probe.py 把頁面、匯出、同步、偵測都跑一遍。

只能對名稱以 `_scale` 結尾的資料庫跑。位址一律用 10.0.0.0/8 私網、MAC 一律用本地管理位址
（02:00:…），不抄任何實機資料。規模可用環境變數調（預設約：2,000 個 /24 ＋ 一個滿的 /16、
14.5 萬個 IP、2 萬台裝置、20 萬個連接埠（其中一台 4 萬個）、15 萬 ARP、30 萬 FDB、
10 萬租約、50 萬筆 IP 異動、100 萬筆逐日上線）。

用法：
    cd backend
    set -a; source /opt/jt-ipam/.dev.env; set +a
    createdb …jt_ipam_scale；POSTGRES_DB=jt_ipam_scale .venv/bin/alembic upgrade head
    POSTGRES_DB=jt_ipam_scale .venv/bin/python -m tests.seed_scale
"""
from __future__ import annotations

import asyncio
import os
import time

N24 = int(os.environ.get("SCALE_SUBNETS", "2000"))          # /24 子網路數
IPS_PER_24 = int(os.environ.get("SCALE_IPS_PER_24", "40"))
N_DEV = int(os.environ.get("SCALE_DEVICES", "20000"))
PORTS_PER_DEV = int(os.environ.get("SCALE_PORTS_PER_DEVICE", "8"))
BIG_DEV_PORTS = int(os.environ.get("SCALE_BIG_DEVICE_PORTS", "40000"))
N_LNMS_DEV = int(os.environ.get("SCALE_LIBRENMS_DEVICES", "5000"))
N_LEASES = int(os.environ.get("SCALE_LEASES", "100000"))
N_RESERVATIONS = int(os.environ.get("SCALE_RESERVATIONS", "20000"))
N_CHANGES = int(os.environ.get("SCALE_CHANGES", "500000"))
LIVENESS_DAYS = int(os.environ.get("SCALE_LIVENESS_DAYS", "7"))
N_WAZUH = int(os.environ.get("SCALE_WAZUH_AGENTS", "30000"))
N_CABLES = int(os.environ.get("SCALE_CABLES", "20000"))

# 數字 → 本地管理 MAC（02:00:xx:xx:xx:xx）
_MAC = ("('02:00:'||lpad(to_hex(({n}>>24)&255),2,'0')||':'||lpad(to_hex(({n}>>16)&255),2,'0')||':'"
        "||lpad(to_hex(({n}>>8)&255),2,'0')||':'||lpad(to_hex({n}&255),2,'0'))::macaddr")


def _guard() -> None:
    name = os.environ.get("POSTGRES_DB", "")
    if not name.endswith("_scale"):
        raise SystemExit(f"POSTGRES_DB={name!r} —— 這支只能對 *_scale 的拋棄式資料庫跑。")


STEPS: list[tuple[str, str]] = [
    ("sections", "INSERT INTO sections (name) SELECT 'scale-sec-'||g FROM generate_series(1, 20) g"),
    ("subnets /24", f"""
        INSERT INTO subnets (cidr, section_id, description)
        SELECT format('10.%s.%s.0/24', g / 256, g % 256)::cidr,
               (SELECT id FROM sections WHERE name = 'scale-sec-'||(1 + g % 20)), 'scale'
        FROM generate_series(0, {N24} - 1) g"""),
    ("subnet /16", """
        INSERT INTO subnets (cidr, section_id, description)
        VALUES ('10.200.0.0/16', (SELECT id FROM sections WHERE name = 'scale-sec-1'), 'scale-big')"""),
    ("ips in /24", f"""
        INSERT INTO ip_addresses (ip, subnet_id, hostname, mac, effective_status)
        SELECT host(s.cidr::inet + h)::inet, s.id, 'h-'||replace(host(s.cidr::inet + h), '.', '-'),
               {_MAC.format(n="(abs(hashtext(host(s.cidr::inet + h))))")},
               CASE WHEN h % 5 = 0 THEN 'offline' ELSE 'online' END
        FROM subnets s, generate_series(1, {IPS_PER_24}) h WHERE s.description = 'scale'"""),
    ("ips in /16 (full)", f"""
        INSERT INTO ip_addresses (ip, subnet_id, hostname, mac, effective_status)
        SELECT host('10.200.0.0'::inet + h)::inet, s.id, NULL,
               {_MAC.format(n="(16777216 + h)")}, CASE WHEN h % 3 = 0 THEN 'offline' ELSE 'online' END
        FROM subnets s, generate_series(1, 65534) h WHERE s.description = 'scale-big'"""),
    ("devices", f"""
        INSERT INTO devices (name, type)
        SELECT 'scale-dev-'||lpad(g::text, 5, '0'), (ARRAY['server','switch','router','firewall'])[1 + g % 4]
        FROM generate_series(1, {N_DEV}) g"""),
    ("big device", "INSERT INTO devices (name, type) VALUES ('scale-hyperv-01', 'server')"),
    ("device primary ips", """
        WITH d AS (SELECT id, row_number() OVER (ORDER BY name) rn FROM devices WHERE name LIKE 'scale-dev-%'),
             i AS (SELECT id, row_number() OVER (ORDER BY ip) rn FROM ip_addresses
                   WHERE subnet_id IN (SELECT id FROM subnets WHERE description = 'scale'))
        UPDATE devices SET primary_ip_id = i.id FROM d JOIN i USING (rn) WHERE devices.id = d.id"""),
    ("ip device links", """
        UPDATE ip_addresses SET device_id = d.id FROM devices d WHERE d.primary_ip_id = ip_addresses.id"""),
    ("device ports", f"""
        INSERT INTO device_ports (device_id, name, type)
        SELECT d.id, 'eth'||p, 'network' FROM devices d, generate_series(0, {PORTS_PER_DEV} - 1) p
        WHERE d.name LIKE 'scale-dev-%'"""),
    ("big device ports", f"""
        INSERT INTO device_ports (device_id, name, type)
        SELECT d.id, 'ethernet_'||p, 'network' FROM devices d, generate_series(0, {BIG_DEV_PORTS} - 1) p
        WHERE d.name = 'scale-hyperv-01'"""),
    ("librenms instance", """
        INSERT INTO librenms_instances (name, api_url, api_token_enc, api_token_nonce)
        VALUES ('scale-lnms', 'https://librenms.example', '\\x00', '\\x00')"""),
    ("librenms devices", f"""
        INSERT INTO librenms_devices (instance_id, legacy_device_id, hostname, jt_ipam_device_id, status, type)
        SELECT (SELECT id FROM librenms_instances WHERE name = 'scale-lnms'), rn, d.name, d.id, 'up', 'network'
        FROM (SELECT id, name, row_number() OVER (ORDER BY name) rn FROM devices WHERE name LIKE 'scale-dev-%') d
        WHERE rn <= {N_LNMS_DEV}"""),
    ("arp", f"""
        INSERT INTO arp_entries (ip, mac, instance_id, device_id, interface, subnet_id)
        SELECT i.ip, i.mac, l.instance_id, l.id, 'vlan'||(i.rn % 50), i.subnet_id
        FROM (SELECT ip, mac, subnet_id, row_number() OVER (ORDER BY ip) rn FROM ip_addresses) i
        JOIN (SELECT id, instance_id, row_number() OVER (ORDER BY legacy_device_id) - 1 k FROM librenms_devices) l
          ON l.k = i.rn % {N_LNMS_DEV}
        WHERE i.rn <= 150000"""),
    ("fdb", f"""
        INSERT INTO fdb_entries (mac, vlan_id_num, instance_id, device_id, port_name)
        SELECT a.mac, 1 + (a.rn % 50), a.instance_id, l.id, 'ge-0/0/'||(a.rn % 48)
        FROM (SELECT mac, instance_id, row_number() OVER (ORDER BY ip) rn FROM arp_entries) a
        JOIN (SELECT id, row_number() OVER (ORDER BY legacy_device_id) - 1 k FROM librenms_devices) l
          ON l.k = a.rn % {N_LNMS_DEV}
        UNION ALL
        SELECT a.mac, 1 + (a.rn % 50), a.instance_id, l.id, 'xe-0/1/'||(a.rn % 4)
        FROM (SELECT mac, instance_id, row_number() OVER (ORDER BY ip) rn FROM arp_entries) a
        JOIN (SELECT id, row_number() OVER (ORDER BY legacy_device_id) - 1 k FROM librenms_devices) l
          ON l.k = (a.rn + 1) % {N_LNMS_DEV}"""),
    ("dhcp leases", f"""
        INSERT INTO dhcp_lease_sightings (ip_address_id, source_type, source_id)
        SELECT id, 'kea', '00000000-0000-4000-8000-00000000c0de'
        FROM ip_addresses ORDER BY ip LIMIT {N_LEASES}"""),
    ("dhcp flags", """
        UPDATE ip_addresses SET in_dhcp_lease = true WHERE id IN (SELECT ip_address_id FROM dhcp_lease_sightings)"""),
    ("dhcp reservations", f"""
        INSERT INTO dhcp_reservations (source_type, source_id, source_name, ip, mac, ip_address_id)
        SELECT 'kea', '00000000-0000-4000-8000-00000000c0de', 'scale-kea', host(ip), mac::text, id
        FROM ip_addresses ORDER BY ip DESC LIMIT {N_RESERVATIONS}"""),
    ("ip change log", f"""
        INSERT INTO ip_change_log (ip_id, subnet_id, ip_text, event_type, field, old_value, new_value, created_at)
        SELECT i.id, i.subnet_id, host(i.ip), 'update', 'effective_status',
               CASE WHEN g % 2 = 0 THEN 'online' ELSE 'offline' END,
               CASE WHEN g % 2 = 0 THEN 'offline' ELSE 'online' END,
               now() - make_interval(mins => (g * 7) % 86400)
        FROM (SELECT id, subnet_id, ip, row_number() OVER (ORDER BY ip) - 1 rn FROM ip_addresses) i
        JOIN generate_series(0, {N_CHANGES} - 1) g ON i.rn = g % 145000"""),
    ("liveness days", f"""
        INSERT INTO ip_liveness_days (ip_id, day, up, down, arp_only)
        SELECT id, current_date - d, (hashtext(id::text) + d) % 5 <> 0, (hashtext(id::text) + d) % 5 = 0, false
        FROM ip_addresses, generate_series(0, {LIVENESS_DAYS} - 1) d"""),
    ("hostname reports", """
        INSERT INTO ip_hostname_reports (ip_id, source, origin, hostname)
        SELECT id, 'librenms', 'librenms:scale', coalesce(hostname, 'h-'||replace(host(ip), '.', '-'))
        FROM ip_addresses ORDER BY ip LIMIT 100000"""),
    ("hostname observations", """
        INSERT INTO ip_hostname_observations (ip_id, source, hostname)
        SELECT ip_id, source, hostname FROM ip_hostname_reports"""),
    ("wazuh", f"""
        INSERT INTO wazuh_instances (name, api_url, api_user, api_password_enc, api_password_nonce)
        VALUES ('scale-wazuh', 'https://wazuh.example:55000', 'scale', '\\x00', '\\x00');
        INSERT INTO wazuh_agents (instance_id, agent_id, name, ip, status, os_platform, jt_ipam_address_id)
        SELECT (SELECT id FROM wazuh_instances WHERE name = 'scale-wazuh'), lpad(rn::text, 5, '0'),
               'agent-'||rn, ip, CASE WHEN rn % 10 = 0 THEN 'disconnected' ELSE 'active' END, 'ubuntu', id
        FROM (SELECT id, ip, row_number() OVER (ORDER BY ip) rn FROM ip_addresses) i WHERE rn <= {N_WAZUH}"""),
    ("cables", f"""
        INSERT INTO cables (label, type, status) SELECT 'scale-cable-'||g, 'cat6', 'connected'
        FROM generate_series(1, {N_CABLES}) g;
        WITH c AS (SELECT id, row_number() OVER (ORDER BY label) rn FROM cables WHERE label LIKE 'scale-cable-%'),
             p AS (SELECT id, row_number() OVER (ORDER BY device_id, name) rn FROM device_ports
                   WHERE name = 'eth0')
        INSERT INTO cable_terminations (cable_id, side, object_type, object_id)
        SELECT c.id, s.side, 'device_port', p.id
        FROM c CROSS JOIN (VALUES ('A', 0), ('B', 1)) s(side, off)
        JOIN p ON p.rn = ((c.rn - 1) * 2 + s.off) % {N_DEV} + 1"""),
    ("analyze", "ANALYZE"),
]


async def seed() -> None:
    from sqlalchemy import text

    from app.core.db import engine

    start = os.environ.get("SCALE_FROM_STEP")          # 中途失敗時從某一步接著做
    for name, sql in STEPS:
        if start and name != start:
            continue
        start = None
        t = time.monotonic()
        async with engine.begin() as conn:
            await conn.execute(text("SET LOCAL statement_timeout = 0"))   # 灌資料不受應用程式的逾時限制
            for stmt in [x for x in sql.split(";\n") if x.strip()]:
                res = await conn.execute(text(stmt))
        print(f"{name:24s} {time.monotonic() - t:6.1f}s  rows={getattr(res, 'rowcount', '?')}", flush=True)
    await engine.dispose()


if __name__ == "__main__":
    _guard()
    asyncio.run(seed())
