"""大量值的 IN 條件（GitHub issue #47）。

asyncpg 一個語句最多 32767 個參數，`col.in_(python_list)` 每個值佔一個。清單來自客戶資料時就會
整支失敗：回報者的 LibreNMS 同步在清理某台裝置的連接埠時爆掉
（`InterfaceError: the number of query arguments cannot exceed 32767`）—— 那台裝置身上累積了
三萬多個埠（Windows 的 NDIS 偽網卡一直長，見 device_port_filter）。

- `in_values()` 用一個陣列參數（`col = ANY($1::type[])`），UUID／MACADDR／INET／文字都要能用
- 同步清理、連接埠分頁在一台裝置有三萬多個埠時照常運作
"""
from __future__ import annotations

import time
import uuid

from app.core.sqlin import in_values
from app.models.device import Device
from app.models.librenms import LibreNMSDevice, LibreNMSInstance
from app.models.physical import DevicePort
from sqlalchemy import String, cast, func, insert, literal, select
from sqlalchemy.dialects.postgresql import INET, MACADDR

N = 33_000          # 超過 32767


async def test_in_values_takes_one_parameter_for_any_number_of_values(db_session) -> None:
    ids = [uuid.uuid4() for _ in range(40_000)]
    hit = ids[12_345]
    assert (await db_session.execute(select(in_values(cast(literal(str(hit)), DevicePort.id.type), ids)))).scalar()
    assert not (await db_session.execute(
        select(in_values(cast(literal(str(uuid.uuid4())), DevicePort.id.type), ids)))).scalar()
    macs = [f"00:00:5e:{i // 65536 % 256:02x}:{i // 256 % 256:02x}:{i % 256:02x}" for i in range(40_000)]
    assert (await db_session.execute(select(in_values(cast(literal("00:00:5e:00:9c:3f"), MACADDR), macs)))).scalar()
    ips = [f"198.18.{i // 256}.{i % 256}" for i in range(40_000)]
    assert (await db_session.execute(select(in_values(cast(literal("198.18.100.7"), INET), ips)))).scalar()
    assert (await db_session.execute(select(in_values(cast(literal("x-39999"), String),
                                                      [f"x-{i}" for i in range(40_000)])))).scalar()
    # host(inet) 這類函式沒有型別：指定成文字
    assert (await db_session.execute(select(in_values(func.host(cast(literal("198.18.0.9"), INET)), ips,
                                                      type_=String())))).scalar()
    # 空清單＝沒有符合的（與 in_([]) 相同）
    assert not (await db_session.execute(select(in_values(cast(literal(str(hit)), DevicePort.id.type), [])))).scalar()


async def _device_with_ports(db, names: list[str], origin: str | None = None) -> Device:
    dev = Device(name=f"ws-{uuid.uuid4().hex[:6]}")
    db.add(dev)
    await db.flush()
    await db.execute(insert(DevicePort), [
        {"device_id": dev.id, "name": n, "type": "network", "source_origin": origin} for n in names])
    return dev


async def _count(db, dev: Device) -> int:
    return (await db.execute(select(func.count()).select_from(DevicePort).where(
        DevicePort.device_id == dev.id))).scalar()


async def test_pruning_tens_of_thousands_of_pseudo_ports(db_session) -> None:
    from app.services.device_port_filter import load_patterns, prune_pseudo_ports

    db_session.autoflush = False
    dev = await _device_with_ports(db_session, ["eth0", *[f"ethernet_{i}" for i in range(N)]])
    await db_session.commit()
    started = time.monotonic()
    pruned = await prune_pseudo_ports(db_session, dev.id, await load_patterns(db_session))
    await db_session.commit()
    assert pruned == N
    assert await _count(db_session, dev) == 1
    assert time.monotonic() - started < 60          # 外鍵沒索引時要將近兩分鐘


async def test_reconciling_tens_of_thousands_of_ports_that_librenms_no_longer_reports(db_session) -> None:
    from app.services import librenms as lib

    db_session.autoflush = False
    inst = LibreNMSInstance(name=f"lnms-{uuid.uuid4().hex[:6]}", api_url="https://librenms.example",
                            api_token_enc=b"x", api_token_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    origin = lib.port_origin(inst.id)
    dev = await _device_with_ports(db_session, [f"veth{i}" for i in range(N)] + ["eno1"], origin=origin)
    db_session.add(LibreNMSDevice(instance_id=inst.id, legacy_device_id=7, jt_ipam_device_id=dev.id))
    await db_session.commit()
    removed = await lib.reconcile_librenms_ports(db_session, dev.id, origin, {"eno1"})
    await db_session.commit()
    assert removed == N
    assert await _count(db_session, dev) == 1


async def test_ports_tab_of_a_device_with_tens_of_thousands_of_ports(client, auth_headers, db_session) -> None:
    dev = await _device_with_ports(db_session, [f"ethernet_{i}" for i in range(N)])
    await db_session.commit()
    r = await client.get(f"/api/v1/device-ports?device_id={dev.id}", headers=auth_headers)
    assert r.status_code == 200, r.text[:300]


def test_in_values_refuses_a_subquery() -> None:
    """子查詢沒有參數上限的問題，本來就該用 .in_(select(...))；誤傳進來要講清楚，而不是在執行時才爆。"""
    import pytest
    from app.core.sqlin import not_in_values
    sub = select(DevicePort.id).where(DevicePort.peer_port_id.is_not(None))
    with pytest.raises(TypeError, match="subquery"):
        in_values(DevicePort.id, sub)
    with pytest.raises(TypeError, match="subquery"):
        not_in_values(DevicePort.id, sub)


# ─────────────────── 守門：同步與大量資料路徑上不可以再出現 .in_(Python 清單) ───────────────────

# 這些模組處理的清單會隨網路規模成長（某台裝置的所有埠、整個網段的 IP、所有租約、所有代理…）
_SCALE_SENSITIVE = [
    "app/services/librenms.py", "app/services/hostname_reports.py", "app/services/dhcp_leases.py",
    "app/services/dhcp_reservations.py", "app/services/device_port_filter.py", "app/services/uptime.py",
    "app/services/anomaly.py", "app/services/topology.py", "app/services/wazuh.py",
    "app/services/proxmox.py", "app/services/ocs.py", "app/api/v1/endpoints/physical.py",
    "app/services/agent_scope.py",
]


def _unbounded_in_calls(path: str) -> list[str]:
    """`.in_()`／`.not_in()`／`.notin_()` 的參數是 Python 集合（不是常數、子查詢、子網路範圍）的地方。

    合法的例外在同一行寫 `# bounded: <理由>`（一頁的筆數、一台裝置的 VLAN…）。
    """
    import ast
    import re
    from pathlib import Path

    ok_name = re.compile(r"^[A-Z_][A-Z0-9_]*$")
    full = Path(path) if Path(path).is_absolute() else Path(__file__).resolve().parent.parent / path
    src = full.read_text(encoding="utf-8")
    lines = src.splitlines()

    def is_select(node: ast.AST) -> bool:          # select(...) 或 select(...).where(...)...
        while isinstance(node, ast.Call):
            f = node.func
            if getattr(f, "id", None) == "select" or getattr(f, "attr", None) == "select":
                return True
            node = f.value if isinstance(f, ast.Attribute) else None
        return False

    out = []
    for fn in ast.walk(ast.parse(src)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        selects = {t.id for n in ast.walk(fn) if isinstance(n, ast.Assign) and is_select(n.value)
                   for t in n.targets if isinstance(t, ast.Name)}
        for n in ast.walk(fn):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr in ("in_", "not_in", "notin_") and n.args):
                continue
            a = n.args[0]
            if isinstance(a, ast.Constant) or (isinstance(a, (ast.Tuple, ast.List, ast.Set))
                                               and all(isinstance(e, ast.Constant) for e in a.elts)):
                continue
            if is_select(a) or (isinstance(a, ast.Name) and (a.id in selects or ok_name.search(a.id))):
                continue
            if isinstance(a, ast.Attribute) and ok_name.search(a.attr):
                continue
            if "# bounded" in lines[n.lineno - 1]:
                continue
            out.append(f"{path}:{n.lineno}: {lines[n.lineno - 1].strip()[:110]}")
    return out


def test_no_unbounded_in_lists_on_scale_sensitive_paths() -> None:
    """整個 app/ 都要守（2026-09-30 起）：非管理員帳號的可見範圍是把 id 集合帶進 `.in_()`，
    被授權整個單位的部門帳號看得到超過 32767 個物件時，**每一個**清單端點與 AI 工具都 500 ——
    只守同步模組的時候完全沒抓到（tests/test_visibility_scale.py）。"""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    paths = sorted({str(p.relative_to(root)) for p in (root / "app").rglob("*.py")} | set(_SCALE_SENSITIVE))
    assert len(paths) > 300
    found = [x for p in paths for x in _unbounded_in_calls(p)]
    assert found == [], ("清單會隨網路規模成長的地方要用 app.core.sqlin.in_values()／not_in_values()，"
                         "天然有上限的在同一行註明 `# bounded: <理由>`：\n" + "\n".join(found))


def test_the_guard_sees_an_unbounded_in(tmp_path) -> None:
    """守門本身要抓得到（不然就是形同虛設），也要放過子查詢、常數與註明有上限的。"""
    probe = tmp_path / "probe.py"
    probe.write_text(
        "async def f(s, ids, subnet_ids):\n"
        "    a = select(X).where(X.id.in_(ids))\n"                       # 抓
        "    sub = select(Y.id).where(Y.ok)\n"
        "    b = select(X).where(X.id.not_in(sub), X.k.in_(('a', 'b')))\n"  # 子查詢、常數：放過
        "    c = select(X).where(X.subnet_id.in_(subnet_ids))\n"         # 子網路清單也抓（可見範圍就叫這個名字）
        "    d = select(X).where(X.id.in_(ids))  # bounded: one page\n",  # 有註明：放過
        encoding="utf-8")
    found = _unbounded_in_calls(str(probe))
    assert len(found) == 2
    assert ":2:" in found[0]
    assert ":5:" in found[1]


async def test_missing_agents_scope_for_tens_of_thousands_of_addresses(db_session) -> None:
    """Wazuh／OCS「未裝 Agent」頁替每個 IP 補子網路／區段／單位：大站台一次就是幾萬個（超大規模測試抓到）。"""
    from app.services.agent_scope import annotate_scope
    rows = [{"ip_address_id": str(uuid.uuid4())} for _ in range(N)]
    out = await annotate_scope(db_session, rows)
    assert len(out) == N


async def test_oui_search_without_criteria_is_a_bad_request(client, auth_headers) -> None:
    """服務層丟的是 UiError（不是 ValueError）：以前沒接住，變成 500。"""
    r = await client.get("/api/v1/oui/search", headers=auth_headers)
    assert r.status_code == 400, r.text


async def test_subnet_blocks_summarise_every_24_server_side(client, auth_headers, db_session) -> None:
    """/16 的 IP 指示計：前端只載入前 1,000 個位址，拿它畫會只剩四格、還寫著「只列有登記的區塊」。
    改由後端直接彙總每個 /24 的已用數。"""
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(cidr="10.77.0.0/16", section_id=sec.id)
    db_session.add(sn)
    await db_session.flush()
    await db_session.execute(IPAddress.__table__.insert(), [
        {"subnet_id": sn.id, "ip": f"10.77.{b}.{h}"} for b in (0, 5, 200) for h in range(1, 1 + b % 7 + 3)])
    await db_session.commit()
    r = await client.get(f"/api/v1/subnets/{sn.id}/blocks", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json() == {"prefix": 24, "blocks": [
        {"start": "10.77.0.0", "used": 3}, {"start": "10.77.5.0", "used": 8}, {"start": "10.77.200.0", "used": 7}]}
    assert (await client.get(f"/api/v1/subnets/{uuid.uuid4()}/blocks", headers=auth_headers)).status_code in (403, 404)


async def test_hostname_run_writes_in_batches(db_session) -> None:
    """一輪回報幾萬個名稱（大型 DHCP、LibreNMS）：以前每個 IP 各一次 upsert（十萬個名稱＝十萬次查詢）。"""
    from app.models.address import IPAddress
    from app.models.ip_hostname import IPHostnameReport
    from app.models.section import Section
    from app.models.subnet import Subnet
    from app.services.hostname_reports import HostnameRun
    from sqlalchemy import event

    db_session.autoflush = False
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(cidr="10.66.0.0/16", section_id=sec.id)
    db_session.add(sn)
    await db_session.flush()
    n = 12_000
    await db_session.execute(insert(IPAddress), [{"subnet_id": sn.id, "ip": f"10.66.{i // 256}.{i % 256}"}
                                                 for i in range(n)])
    await db_session.commit()
    ips = (await db_session.execute(select(IPAddress).where(IPAddress.subnet_id == sn.id))).scalars().all()

    async def one_round() -> int:
        run = HostnameRun(db_session, source="kea_dhcp", origin="kea_dhcp:scale")
        for ip in ips:
            run.report(ip, f"host-{str(ip.ip).replace('.', '-')}")
        count = {"n": 0}
        conn = await db_session.connection()

        def _c(*_a, **_k):
            count["n"] += 1
        event.listen(conn.sync_connection, "before_cursor_execute", _c)
        try:
            await run.finish(complete=True)
            await db_session.commit()
        finally:
            event.remove(conn.sync_connection, "before_cursor_execute", _c)
        return count["n"]

    await one_round()                       # 第一輪：名稱第一次出現，要寫觀測值（跟名稱數成正比是對的）
    second = await one_round()              # 第二輪：什麼都沒變
    assert second < 60, f"沒有變動的一輪查了 {second} 次"
    rows = (await db_session.execute(select(func.count()).select_from(IPHostnameReport).where(
        IPHostnameReport.origin == "kea_dhcp:scale"))).scalar()
    assert rows == n


async def test_lease_run_writes_in_batches(db_session) -> None:
    """大型 DHCP 一輪十萬筆租約：以前每筆各一次 upsert。"""
    from app.models.address import IPAddress
    from app.models.dhcp import DHCPLeaseSighting
    from app.models.section import Section
    from app.models.subnet import Subnet
    from app.services.dhcp_leases import LeaseRun
    from sqlalchemy import event

    db_session.autoflush = False
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(cidr="10.65.0.0/16", section_id=sec.id)
    db_session.add(sn)
    await db_session.flush()
    n = 12_000
    await db_session.execute(insert(IPAddress), [{"subnet_id": sn.id, "ip": f"10.65.{i // 256}.{i % 256}"}
                                                 for i in range(n)])
    await db_session.commit()
    ips = (await db_session.execute(select(IPAddress).where(IPAddress.subnet_id == sn.id))).scalars().all()
    source_id = uuid.uuid4()
    for _round in range(2):
        run = LeaseRun(db_session, source_type="kea", source_id=source_id)
        for ip in ips:
            run.saw(ip)
        count = {"n": 0}
        conn = await db_session.connection()

        def _c(*_a, **_k):
            count["n"] += 1
        event.listen(conn.sync_connection, "before_cursor_execute", _c)
        try:
            await run.finish(complete=True)
            await db_session.commit()
        finally:
            event.remove(conn.sync_connection, "before_cursor_execute", _c)
        assert count["n"] < 40, f"第 {_round + 1} 輪查了 {count['n']} 次"
    assert (await db_session.execute(select(func.count()).select_from(DHCPLeaseSighting))).scalar() == n
