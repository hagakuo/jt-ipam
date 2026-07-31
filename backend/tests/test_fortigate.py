"""FortiGate 整合（Beta）。

無實機可驗 → 測試重點在**容錯解析**與「不破壞既有資料」：
欄位缺失／外層形狀不同／某端點掛掉，都不能拖垮整輪同步，也不能亂建 IP。
"""

from __future__ import annotations

import uuid

import pytest
from app.models.fortigate import FortiGateFirewall
from app.services import fortigate as fg
from sqlalchemy import func, select


# ─────────────── 純解析（不需 DB）───────────────
def test_unwrap_tolerates_dict_and_list() -> None:
    """FortiOS 一般回 {"results": [...]}；global=1 等情境可能是外層陣列 → 都要吃得下。"""
    assert fg._unwrap({"results": [{"a": 1}], "status": "success"}) == [{"a": 1}]
    assert fg._unwrap([{"results": [{"a": 1}]}, {"results": [{"b": 2}]}]) == [{"a": 1}, {"b": 2}]
    assert fg._rows({"name": "single"}) == [{"name": "single"}]   # 單筆物件
    assert fg._rows(None) == []


def test_names_flattens_fortios_name_objects() -> None:
    """srcaddr/dstintf 等是 [{"name": ...}] 結構。"""
    assert fg._names([{"name": "port1"}, {"name": "port2"}]) == "port1, port2"
    assert fg._names("lan") == "lan"
    assert fg._names([]) is None
    assert fg._names(None) is None


def test_port_and_mac_and_ip_parsers() -> None:
    assert fg._to_port("80-90") == 80          # 埠可能是範圍字串
    assert fg._to_port("443") == 443
    assert fg._to_port("any") is None
    assert fg._norm_mac("AA-BB-CC-11-22-33") == "aa:bb:cc:11:22:33"
    assert fg._norm_mac("nope") is None
    assert fg._valid_ip("10.0.0.5/24") == "10.0.0.5"
    assert fg._valid_ip("Web_Server_Alias") is None   # 別名不是 IP


# ─────────────── DB-backed ───────────────
async def _mk_fw(session, name="fgt-test", vdoms=None):  # type: ignore[no-untyped-def]
    fw = FortiGateFirewall(
        name=name, api_url="https://192.0.2.1",
        api_token_enc=b"x", api_token_nonce=b"x", vdoms=vdoms,
    )
    session.add(fw)
    await session.flush()
    return fw


def _patch_api(monkeypatch, mapping, fail: set[str] | None = None):
    """以 path 為鍵回假資料；fail 內的 path 直接丟 FortiGateError（模擬端點不存在／無權限）。"""
    async def fake(_fw, path, *, vdom=None, timeout=15.0):  # type: ignore[no-untyped-def]
        if fail and path in fail:
            raise fg.FortiGateError("simulated endpoint failure")
        val = mapping.get(path, [])
        return val(vdom) if callable(val) else val
    monkeypatch.setattr(fg, "_api_get", fake)


@pytest.mark.anyio
async def test_list_vdoms_prefers_config_then_discovery_then_root(db_session, monkeypatch) -> None:
    fw = await _mk_fw(db_session, "fgt-vdom", vdoms=["v1", "v2"])
    _patch_api(monkeypatch, {})
    assert await fg.list_vdoms(fw) == ["v1", "v2"]          # 使用者指定優先

    fw2 = await _mk_fw(db_session, "fgt-auto")
    _patch_api(monkeypatch, {fg.EP_VDOMS: [{"name": "root"}, {"name": "guest"}]})
    assert await fg.list_vdoms(fw2) == ["root", "guest"]    # 自動探索

    _patch_api(monkeypatch, {}, fail={fg.EP_VDOMS})
    assert await fg.list_vdoms(fw2) == ["root"]             # 非 VDOM 模式 → 退回 root


@pytest.mark.anyio
async def test_dhcp_and_arp_stamp_existing_only(db_session, admin_user, monkeypatch) -> None:
    """租約／ARP 只標記既有 IP，絕不新建（與 OPNsense/pfSense 一致）。"""
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet

    sect = Section(name="fg-sec")
    db_session.add(sect)
    await db_session.flush()
    sub = Subnet(section_id=sect.id, cidr="10.7.0.0/24")
    db_session.add(sub)
    await db_session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="10.7.0.10")
    db_session.add(ipa)
    await db_session.flush()

    fw = await _mk_fw(db_session, "fgt-dhcp", vdoms=["root"])
    _patch_api(monkeypatch, {
        fg.EP_DHCP_LEASES: [
            {"ip": "10.7.0.10", "mac": "aa:bb:cc:00:11:22", "hostname": "pc-fg",
             "reserved": False, "status": "leased"},
            {"ip": "10.7.0.99", "mac": "aa:bb:cc:00:11:33"},   # IPAM 沒有 → 不建
        ],
        fg.EP_ARP: [{"ip": "10.7.0.10", "mac": "aa:bb:cc:00:11:22", "interface": "port1"}],
    })
    before = await db_session.scalar(select(func.count()).select_from(IPAddress))
    assert await fg.sync_dhcp_leases(db_session, fw, ["root"]) == 1
    assert await fg.sync_arp(db_session, fw, ["root"]) == 1
    after = await db_session.scalar(select(func.count()).select_from(IPAddress))

    assert after == before                     # 沒有新建 IP
    await db_session.refresh(ipa)
    assert ipa.in_dhcp_lease is True
    assert ipa.hostname == "pc-fg"
    assert str(ipa.mac).lower() == "aa:bb:cc:00:11:22"


@pytest.mark.anyio
async def test_dhcp_ranges_written_with_own_source(db_session, admin_user, monkeypatch) -> None:
    """發放範圍寫進共用表，source_type='fortigate'（ip-range 是巢狀清單）。"""
    from app.models.dhcp import DHCPPoolRange
    fw = await _mk_fw(db_session, "fgt-range", vdoms=["root"])
    _patch_api(monkeypatch, {fg.EP_DHCP_SERVERS: [
        {"interface": "internal", "status": "enable",
         "ip-range": [{"start-ip": "10.7.0.100", "end-ip": "10.7.0.200"},
                      {"start-ip": "10.7.0.210", "end-ip": "10.7.0.220"}]},
        {"interface": "dmz", "status": "disable",      # 停用 → 略過
         "ip-range": [{"start-ip": "10.8.0.10", "end-ip": "10.8.0.20"}]},
    ]})
    assert await fg.sync_dhcp_ranges(db_session, fw, ["root"]) == 2
    rows = (await db_session.execute(select(DHCPPoolRange).where(
        DHCPPoolRange.source_type == "fortigate", DHCPPoolRange.source_id == fw.id,
    ))).scalars().all()
    assert sorted((r.start_ip, r.end_ip) for r in rows) == [
        ("10.7.0.100", "10.7.0.200"), ("10.7.0.210", "10.7.0.220")]


@pytest.mark.anyio
async def test_nat_vip_and_ippool(db_session, admin_user, monkeypatch) -> None:
    """VIP 的 mappedip 是 [{"range": ...}]；external_id 帶 VDOM 首碼且不與其他來源衝突。"""
    from app.models.nat import NATTranslation
    fw = await _mk_fw(db_session, "fgt-nat", vdoms=["root"])
    _patch_api(monkeypatch, {
        fg.EP_VIP: [{"name": "web-vip", "extip": "203.0.113.10", "extport": "443",
                     "mappedip": [{"range": "10.7.0.10"}], "mappedport": "8443",
                     "portforward": "enable", "protocol": "tcp", "comment": "web"}],
        fg.EP_IPPOOL: [{"name": "snat-pool", "startip": "203.0.113.20",
                        "endip": "203.0.113.29"}],
    })
    assert await fg.sync_nat(db_session, fw, ["root"]) == 2
    rows = (await db_session.execute(select(NATTranslation).where(
        NATTranslation.source_origin == f"fortigate:{fw.id}"))).scalars().all()
    by_name = {r.name: r for r in rows}
    assert by_name["web-vip"].type == "port_forward"
    assert by_name["web-vip"].dst_port == 8443
    assert by_name["web-vip"].external_id == "root:web-vip"
    assert by_name["snat-pool"].type == "many_to_one"
    assert "203.0.113.20-203.0.113.29" in (by_name["snat-pool"].description or "")


@pytest.mark.anyio
async def test_vpn_status_from_nested_proxyid(db_session, admin_user, monkeypatch) -> None:
    """IPsec 狀態在巢狀 proxyid[].status；SSL-VPN 配發 IP 在 subsessions[].aip。"""
    from app.models.address import IPAddress
    from app.models.physical import VPNTunnel
    from app.models.section import Section
    from app.models.subnet import Subnet

    sect = Section(name="fg-vpn-sec")
    db_session.add(sect)
    await db_session.flush()
    sub = Subnet(section_id=sect.id, cidr="10.212.134.0/24")
    db_session.add(sub)
    await db_session.flush()
    db_session.add(IPAddress(subnet_id=sub.id, ip="10.212.134.5"))
    await db_session.flush()

    fw = await _mk_fw(db_session, "fgt-vpn", vdoms=["root"])
    _patch_api(monkeypatch, {
        fg.EP_VPN_IPSEC: [
            {"name": "to-branch", "rgwy": "198.51.100.7", "type": "automatic",
             "proxyid": [{"p2name": "to-branch-sub", "status": "up"}]},
            {"name": "to-dr", "rgwy": "198.51.100.8",
             "proxyid": [{"p2name": "x", "status": "down"}]},
        ],
        fg.EP_VPN_SSL: [
            {"user_name": "u1", "remote_host": "203.0.113.55",
             "subsessions": [{"aip": "10.212.134.5"}]},
        ],
    })
    out = await fg.sync_vpn(db_session, fw, ["root"])
    assert out["tunnels"] == 2
    assert out["ssl_sessions"] == 1

    tuns = {t.name: t for t in (await db_session.execute(
        select(VPNTunnel).where(VPNTunnel.name.like("fgt-vpn/ipsec/%")))).scalars().all()}
    assert tuns["fgt-vpn/ipsec/root/to-branch"].status == "active"
    assert tuns["fgt-vpn/ipsec/root/to-dr"].status == "offline"
    assert tuns["fgt-vpn/ipsec/root/to-branch"].b_endpoint == "198.51.100.7"


@pytest.mark.anyio
async def test_policies_and_addresses_mirror(db_session, admin_user, monkeypatch) -> None:
    from app.models.fortigate import FortiGateAddressObject, FortiGatePolicy
    fw = await _mk_fw(db_session, "fgt-obj", vdoms=["root"])
    _patch_api(monkeypatch, {
        fg.EP_POLICY: [{"policyid": 1, "name": "allow-out", "status": "enable",
                        "action": "accept", "srcintf": [{"name": "internal"}],
                        "dstintf": [{"name": "wan1"}], "srcaddr": [{"name": "all"}],
                        "dstaddr": [{"name": "all"}], "service": [{"name": "ALL"}],
                        "nat": "enable", "comments": "c"}],
        fg.EP_ADDRESS: [
            {"name": "srv1", "type": "ipmask", "subnet": "10.7.0.10 255.255.255.255"},
            {"name": "rng1", "type": "iprange", "start-ip": "10.7.0.20", "end-ip": "10.7.0.30"},
        ],
        fg.EP_ADDRGRP: [{"name": "grp1", "member": [{"name": "srv1"}, {"name": "rng1"}]}],
    })
    assert await fg.sync_policies(db_session, fw, ["root"]) == 1
    assert await fg.sync_addresses(db_session, fw, ["root"]) == 3

    pol = (await db_session.execute(select(FortiGatePolicy).where(
        FortiGatePolicy.firewall_id == fw.id))).scalars().one()
    assert (pol.policyid, pol.srcintf, pol.nat) == ("1", "internal", True)

    objs = {o.name: o for o in (await db_session.execute(select(FortiGateAddressObject).where(
        FortiGateAddressObject.firewall_id == fw.id))).scalars().all()}
    assert objs["srv1"].value == "10.7.0.10/255.255.255.255"
    assert objs["rng1"].value == "10.7.0.20-10.7.0.30"
    assert objs["grp1"].kind == "group"
    assert objs["grp1"].members == ["srv1", "rng1"]


@pytest.mark.anyio
async def test_failing_endpoint_does_not_break_other_syncs(db_session, admin_user, monkeypatch) -> None:
    """某端點掛掉（版本差異／無權限）→ 該項回 0，其他項照常（容錯的核心保證）。"""
    fw = await _mk_fw(db_session, "fgt-partial", vdoms=["root"])
    fw.sync_dhcp_ranges = True
    fw.sync_policies = True
    fw.sync_arp = False
    _patch_api(monkeypatch, {
        fg.EP_POLICY: [{"policyid": 7, "name": "p7"}],
    }, fail={fg.EP_DHCP_SERVERS})     # DHCP server 端點不可用
    out = await fg.sync_instance(db_session, fw)
    assert out["dhcp_ranges"] == 0    # 掛掉的項目回 0
    assert out["policies"] == 1       # 其他項不受影響
    assert fw.last_error is None


@pytest.mark.anyio
async def test_delete_firewall_cleans_shared_tables(db_session, admin_user, monkeypatch) -> None:
    """刪 FortiGate 要清掉共用表裡自己的列，且不動其他來源（無外鍵 cascade 可依靠）。"""
    from app.models.dhcp import DHCPPoolRange
    from app.models.nat import NATTranslation
    fw = await _mk_fw(db_session, "fgt-del", vdoms=["root"])
    db_session.add(DHCPPoolRange(
        source_type="fortigate", source_id=fw.id, source_name=fw.name,
        subnet_cidr="internal", start_ip="10.7.0.1", end_ip="10.7.0.9", family=4,
        source="fortigate"))
    db_session.add(DHCPPoolRange(
        source_type="opnsense", source_id=uuid.uuid4(), source_name="other",
        subnet_cidr="10.9.0.0/24", start_ip="10.9.0.1", end_ip="10.9.0.9", family=4,
        source="kea"))
    db_session.add(NATTranslation(
        name="fg-nat", type="port_forward", source_origin=f"fortigate:{fw.id}",
        external_id="root:x"))
    await db_session.commit()

    # 呼叫端點真正用的那個清理函式，不要在測試裡重寫一份同樣的 DELETE ——
    # 否則端點漏清共用表，這個測試照樣會綠。
    from app.api.v1.endpoints.fortigate import cleanup_shared_rows

    await cleanup_shared_rows(db_session, fw.id)
    await db_session.flush()

    assert await db_session.scalar(select(func.count()).select_from(DHCPPoolRange).where(
        DHCPPoolRange.source_type == "fortigate")) == 0
    assert await db_session.scalar(select(func.count()).select_from(DHCPPoolRange).where(
        DHCPPoolRange.source_type == "opnsense")) == 1      # 其他來源不受影響
    assert await db_session.scalar(select(func.count()).select_from(NATTranslation).where(
        NATTranslation.source_origin == f"fortigate:{fw.id}")) == 0


@pytest.mark.anyio
async def test_diagnose_probes_run_concurrently(monkeypatch) -> None:
    """診斷的 10 支探測必須並行。

    循序跑的話，對「不可達主機」（IP 填錯／防火牆丟包 —— 客戶第一次設定最常遇到的
    情況）會累加成 10 × 逾時 ≈ 100 秒，前端診斷視窗看起來像凍住。
    """
    import asyncio
    import time
    import types

    async def slow_get(fw, path, *, vdom=None, timeout=15.0):
        await asyncio.sleep(0.3)                     # 模擬等到逾時
        raise fg.FortiGateError("transport: ConnectTimeout")

    monkeypatch.setattr(fg, "_api_get", slow_get)
    fw = types.SimpleNamespace(
        id=uuid.uuid4(), api_url="https://192.0.2.241", vdoms=["root"],
        verify_tls=False, scope_subnet_ids=None, name="bh",
    )
    started = time.monotonic()
    out = await fg.diagnose(fw)
    elapsed = time.monotonic() - started

    n = len(out["checks"])
    assert n == 10, f"探測數變成 {n}，測試需同步更新"
    # 並行 → 約等於單支耗時；循序會是 n 倍。留寬裕倍數避免 CI 抖動誤判。
    assert elapsed < 0.3 * 4, f"耗時 {elapsed:.2f}s 接近循序（{0.3 * n:.2f}s）→ 並行沒生效"
    # 並行不能犧牲診斷資訊：每支都要各自回報錯誤
    assert all(not c["ok"] and c.get("error") for c in out["checks"])


@pytest.mark.anyio
async def test_vpn_reports_endpoint_unavailable(db_session, admin_user, monkeypatch) -> None:
    """端點讀不到時要明講，不能偽裝成「0 個連線」。

    客戶實測回報 `ssl_sessions: 0` —— 但那有兩種完全不同的意思：「當下沒人連線」
    與「端點失敗被吞掉」。無實機開發時，這正是判斷解析對不對最需要分辨的地方。
    """
    fw = await _mk_fw(db_session, "fgt-vpn-flags", vdoms=["root"])

    # SSL 端點掛掉、IPsec 正常 → 只有 ssl_unavailable
    _patch_api(monkeypatch, {fg.EP_VPN_IPSEC: []}, fail={fg.EP_VPN_SSL})
    out = await fg.sync_vpn(db_session, fw, ["root"])
    assert out["ssl_sessions"] == 0
    assert out.get("ssl_unavailable") is True
    assert "ipsec_unavailable" not in out

    # 兩個都正常且真的沒人連線 → 0 但不得有旗標（才能與「失敗」區分）
    _patch_api(monkeypatch, {fg.EP_VPN_IPSEC: [], fg.EP_VPN_SSL: []})
    out = await fg.sync_vpn(db_session, fw, ["root"])
    assert out["ssl_sessions"] == 0
    assert "ssl_unavailable" not in out
    assert "ipsec_unavailable" not in out

    # 兩個都掛 → 兩個旗標都要有
    _patch_api(monkeypatch, {}, fail={fg.EP_VPN_IPSEC, fg.EP_VPN_SSL})
    out = await fg.sync_vpn(db_session, fw, ["root"])
    assert out.get("ssl_unavailable") is True
    assert out.get("ipsec_unavailable") is True
