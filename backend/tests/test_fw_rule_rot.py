"""防火牆規則劣化偵測：懸空 NAT／any-any 放行／WAN 開管理埠。

這一頁最大的敵人是誤報 —— 異常清單狼來了幾次就沒有人看。所以對抗式重點是
**不該報的都要忍住**：
- 手動建立的 NAT（source_origin 為空）沒有連結 IP 是正常的，不是懸空。
- 已停用（disabled）的 NAT／規則不報 —— 它不在生效路徑上。
- LAN 介面上開 SSH 給 any 是日常，**只有 WAN 類介面**才算管理埠曝險。
- any-any 只抓「放行」；deny any-any 是預設拒絕的正常寫法。
"""
from __future__ import annotations

import uuid

import pytest

from app.models.nat import NATTranslation
from app.services.anomaly import detect_fw_rule_rot


def _pf_rule(**kw):
    base = {"tracker": kw.pop("tracker", uuid.uuid4().hex[:8]), "type": "pass",
            "interface": "lan", "protocol": "tcp",
            "source": "any", "destination": "any", "destination_port": "",
            "descr": "", "disabled": False}
    base.update(kw)
    return base


@pytest.mark.anyio
async def test_dangling_nat_only_flags_synced_enabled_rows(db_session) -> None:
    """懸空 NAT：只報「防火牆同步來的、生效中的、目標不在 IPAM」那種。"""
    db_session.add_all([
        # 該報：pfSense 同步來的 port forward，目標解析不到 IPAM
        NATTranslation(name="pf-dangling", type="port_forward", protocol="tcp",
                       dst_port=8443, source_origin="pfsense:x", disabled=False),
        # 不該報：手動建立（source_origin 空）—— 手動 NAT 沒連 IP 是常態
        NATTranslation(name="manual-no-link", type="port_forward", protocol="tcp",
                       dst_port=80, source_origin=None, disabled=False),
        # 不該報：已停用
        NATTranslation(name="pf-disabled", type="port_forward", protocol="tcp",
                       dst_port=22, source_origin="pfsense:x", disabled=True),
    ])
    await db_session.flush()
    items = await detect_fw_rule_rot(db_session)
    names = {i["name"] for i in items if i["kind"] == "dangling_nat"}
    assert "pf-dangling" in names
    assert "manual-no-link" not in names, "手動 NAT 被誤報成懸空"
    assert "pf-disabled" not in names, "停用中的 NAT 不在生效路徑上，不該報"


@pytest.mark.anyio
async def test_any_any_flags_pass_not_block(db_session) -> None:
    """any-any 只抓放行；block any-any 是預設拒絕的正常寫法。"""
    from app.models.pfsense import PfSenseFirewall

    fw = PfSenseFirewall(name=f"pf-{uuid.uuid4().hex[:6]}", api_url="https://192.0.2.2",
                         api_key_enc=b"x", api_key_nonce=b"y",
                         rules=[
                             _pf_rule(descr="wide open"),                       # 該報
                             _pf_rule(type="block", descr="default deny"),      # 不該報
                             _pf_rule(disabled=True, descr="old wide open"),    # 不該報
                             _pf_rule(destination="192.0.2.10", descr="ok"),    # 不該報
                         ])
    db_session.add(fw)
    await db_session.flush()
    items = await detect_fw_rule_rot(db_session)
    descrs = {i.get("descr") for i in items if i["kind"] == "any_any"}
    assert "wide open" in descrs
    assert descrs.isdisjoint({"default deny", "old wide open", "ok"})


@pytest.mark.anyio
async def test_mgmt_port_only_on_wan_like_interfaces(db_session) -> None:
    """管理埠曝險只看 WAN 類介面：LAN 開 SSH 給 any 是日常，報了就是雜訊。"""
    from app.models.pfsense import PfSenseFirewall

    fw = PfSenseFirewall(name=f"pf-{uuid.uuid4().hex[:6]}", api_url="https://192.0.2.3",
                         api_key_enc=b"x", api_key_nonce=b"y",
                         rules=[
                             _pf_rule(interface="wan", destination="192.0.2.9",
                                      destination_port="3389", descr="rdp from wan"),   # 該報
                             _pf_rule(interface="lan", destination="any",
                                      destination_port="22", descr="lan ssh"),          # 不該報
                         ])
    db_session.add(fw)
    await db_session.flush()
    items = await detect_fw_rule_rot(db_session)
    descrs = {i.get("descr") for i in items if i["kind"] == "mgmt_exposed"}
    assert "rdp from wan" in descrs
    assert "lan ssh" not in descrs


@pytest.mark.anyio
async def test_report_includes_new_category(db_session) -> None:
    """AnomalyReport 要帶 fw_rule_rot（to_dict / total 都要跟上 —— 過去漏過欄位）。"""
    from app.services.anomaly import AnomalyReport

    r = AnomalyReport(fw_rule_rot=[{"kind": "any_any"}])
    d = r.to_dict()
    assert d["fw_rule_rot"] == [{"kind": "any_any"}]
    assert d["total"] >= 1, "新類別沒算進 total —— 儀表板數字會對不上"


@pytest.mark.anyio
async def test_alias_rot_ignores_external_members(db_session) -> None:
    """別名劣化：只報「管理網段內、IPAM 卻沒有」的成員。

    別名裡放外部位址（遠端端點、封鎖清單）是常態 —— 沒有這個門檻，
    每個外部 IP 都會被誤報成劣化。
    """
    from app.models.firewall import OPNsenseFirewall, OPNsenseSyncedAlias
    from app.models.section import Section
    from app.models.subnet import Subnet

    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    # 管理網段（有開異常偵測）
    db_session.add(Subnet(section_id=sec.id, cidr="198.51.100.0/24", anomaly_enabled=True))
    fw = OPNsenseFirewall(name=f"opn-{uuid.uuid4().hex[:6]}", api_url="https://192.0.2.1",
                          api_key_enc=b"x", api_key_nonce=b"y",
                          api_secret_enc=b"x", api_secret_nonce=b"y")
    db_session.add(fw)
    await db_session.flush()
    db_session.add(OPNsenseSyncedAlias(
        firewall_id=fw.id, name="web_servers", alias_type="host", enabled=True,
        content=["198.51.100.50",     # 管理網段內、IPAM 沒有 → 該報
                 "8.8.8.8",           # 外部位址 → 不報
                 "203.0.113.0/24"],   # 網段成員 → 不判定
        member_count=3))
    await db_session.flush()

    items = await detect_fw_rule_rot(db_session)
    rot = [i for i in items if i["kind"] == "alias_rot" and i["name"] == "web_servers"]
    assert len(rot) == 1
    assert "198.51.100.50" in rot[0]["detail"]
    assert "8.8.8.8" not in rot[0]["detail"], "外部位址被誤報成劣化"


@pytest.mark.anyio
async def test_ack_flow(client, auth_headers, db_session) -> None:
    """認領：baseline 不可認領（422）；認領後歷史端點帶出狀態。"""
    from app.services.fw_review import snapshot_if_changed

    fid = uuid.uuid4()
    base = {"key": "1", "action": "pass", "interface": "lan", "protocol": "tcp",
            "src": "any", "src_port": "", "dst": "any", "dst_port": "",
            "descr": "", "disabled": "0"}
    await snapshot_if_changed(db_session, source_type="pfsense", instance_id=fid,
                              instance_name="fw-ack", rules=[base])
    await snapshot_if_changed(db_session, source_type="pfsense", instance_id=fid,
                              instance_name="fw-ack",
                              rules=[base, {**base, "key": "2", "dst_port": "443"}])
    await db_session.commit()
    from sqlalchemy import select as _sel
    from app.models.fw_snapshot import FwRuleSnapshot
    rows = (await db_session.execute(_sel(FwRuleSnapshot).where(
        FwRuleSnapshot.instance_id == fid).order_by(FwRuleSnapshot.taken_at))).scalars().all()

    r = await client.post(f"/api/v1/anomalies/fw-rule-changes/{rows[0].id}/ack",
                          json={"note": "x"}, headers=auth_headers)
    assert r.status_code == 422, "baseline 不需要認領"
    r = await client.post(f"/api/v1/anomalies/fw-rule-changes/{rows[1].id}/ack",
                          json={"note": "開放 443 是我做的，工單 #123"}, headers=auth_headers)
    assert r.status_code == 200
    r = await client.get("/api/v1/anomalies/fw-rule-changes", headers=auth_headers)
    item = next(i for i in r.json()["items"] if i["id"] == str(rows[1].id))
    assert item["ack"] and "工單 #123" in item["ack"]["note"]


@pytest.mark.anyio
async def test_attack_surface_lists_only_determinable_entries(db_session) -> None:
    """攻擊面盤點：只列明確可判定的對外開口，未登錄目標要標警訊。

    稽核拿去簽名的清單不能有猜的成分 —— 目的為別名／any／網段的 WAN 規則不列。
    """
    from app.models.address import IPAddress
    from app.models.pfsense import PfSenseFirewall
    from app.models.section import Section
    from app.models.subnet import Subnet
    from app.services.fw_lookup import attack_surface

    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="198.51.100.7", state="used", hostname="web-a")
    db_session.add(ipa)
    await db_session.flush()

    db_session.add_all([
        NATTranslation(name="pf-web", type="port_forward", protocol="tcp",
                       dst_ip_id=ipa.id, dst_port=443,
                       source_origin="pfsense:x", disabled=False),
        NATTranslation(name="pf-mystery", type="port_forward", protocol="tcp",
                       dst_port=8443, source_origin="pfsense:x", disabled=False),
        NATTranslation(name="pf-off", type="port_forward", protocol="tcp",
                       dst_port=22, source_origin="pfsense:x", disabled=True),
        # 目標 IP 與埠都不明（OPNsense Anti-Lockout 這類自動規則）→ 不可判定，不列
        NATTranslation(name="anti-lockout-like", type="port_forward", protocol="tcp",
                       source_origin="opnsense:x", disabled=False),
    ])
    fw = PfSenseFirewall(name=f"pf-{uuid.uuid4().hex[:6]}", api_url="https://192.0.2.2",
                         api_key_enc=b"x", api_key_nonce=b"y",
                         rules=[
                             {"tracker": "r1", "type": "pass", "interface": "wan",
                              "protocol": "tcp", "source": "any",
                              "destination": "198.51.100.7", "destination_port": "443",
                              "descr": "wan rule", "disabled": False},
                             {"tracker": "r2", "type": "pass", "interface": "wan",
                              "protocol": "tcp", "source": "any",
                              "destination": "web_alias", "destination_port": "80",
                              "descr": "alias dst", "disabled": False},
                             {"tracker": "r3", "type": "pass", "interface": "lan",
                              "protocol": "tcp", "source": "any",
                              "destination": "198.51.100.8", "destination_port": "80",
                              "descr": "lan rule", "disabled": False},
                         ])
    db_session.add(fw)
    await db_session.flush()

    items = await attack_surface(db_session)
    names = {i["name"] for i in items}
    assert "pf-web" in names
    assert "pf-mystery" in names, "懸空轉發是警訊，更要列"
    assert "pf-off" not in names, "停用的不在攻擊面上"
    assert "anti-lockout-like" not in names, "IP 與埠都不明＝不可判定，列了只是噪音"
    web = next(i for i in items if i["name"] == "pf-web")
    assert web["identity"]["registered"] and web["identity"]["hostname"] == "web-a"
    mystery = next(i for i in items if i["name"] == "pf-mystery")
    assert mystery["identity"]["registered"] is False, "未登錄目標要標出來"
    descrs = {i.get("descr") for i in items}
    assert "wan rule" in descrs
    assert "alias dst" not in descrs, "別名目的不可展開猜測"
    assert "lan rule" not in descrs, "LAN 規則不是對外攻擊面"


@pytest.mark.anyio
async def test_attack_surface_attaches_fqdns(db_session) -> None:
    """FQDN 視角：對外開口要能用名字找到（A 直接命中、CNAME 別名也算）。

    稽核問的是「meet.example.net 對外開了什麼」，不是「198.51.100.7 開了什麼」。
    名稱一律取自 IPAM 已同步的 DNS 記錄，不做即時解析（清單必須可重現）。
    """
    from app.models.address import IPAddress
    from app.models.dns import DNSRecord, DNSServer, DNSZone
    from app.models.section import Section
    from app.models.subnet import Subnet
    from app.services.fw_lookup import attack_surface

    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="198.51.100.7", state="used", hostname="web-a")
    db_session.add(ipa)
    await db_session.flush()
    db_session.add(NATTranslation(
        name="pf-web", type="port_forward", protocol="tcp",
        dst_ip_id=ipa.id, dst_port=443, source_origin="pfsense:x", disabled=False))

    srv = DNSServer(name=f"dns-{uuid.uuid4().hex[:6]}", type="bind9", server_address="192.0.2.53")
    db_session.add(srv)
    await db_session.flush()
    zone = DNSZone(server_id=srv.id, name="example.net", type="forward")
    db_session.add(zone)
    await db_session.flush()
    db_session.add_all([
        DNSRecord(zone_id=zone.id, name="web", type="A", value="198.51.100.7"),
        DNSRecord(zone_id=zone.id, name="meet", type="CNAME", value="web.example.net"),
        DNSRecord(zone_id=zone.id, name="other", type="A", value="203.0.113.9"),
    ])
    await db_session.flush()

    items = await attack_surface(db_session)
    web = next(i for i in items if i["name"] == "pf-web")
    fqdns = web["identity"]["fqdns"]
    # 集合比對（清單成員，不是網址子字串）
    assert {"web.example.net"} <= set(fqdns), "A 記錄沒對應到"
    assert {"meet.example.net"} <= set(fqdns), "CNAME 別名也到得了這台，必須列入"
    assert "other.example.net" not in fqdns, "別的 IP 的名稱被錯掛上來"


@pytest.mark.anyio
async def test_dangling_nat_skips_firewall_generated_and_alias_targets(db_session) -> None:
    """防火牆自己產生的規則（OPNsense 的 Anti-Lockout）與目標是別名的轉發都不是懸空。

    正式環境曾把兩台 OPNsense 各三條 Anti-Lockout 報成「埠轉發目標不在 IPAM」——
    那是放行管理介面到防火牆自己的自動規則，沒有目標主機可言。目標是別名的轉發
    解析不到單一 IP 是正常的，別名成員另由「別名劣化」判斷。
    """
    db_session.add_all([
        NATTranslation(name="Anti-Lockout Rule", type="port_forward", protocol="tcp",
                       source_origin="opnsense:x", external_id="lockout_0",
                       category="Automatically generated rules", src_interface="LAN",
                       disabled=False),
        NATTranslation(name="to-alias", type="port_forward", protocol="tcp", dst_port=443,
                       source_origin="opnsense:x", external_id="u-alias",
                       redirect_alias="web_pool", disabled=False),
        NATTranslation(name="real-dangling", type="port_forward", protocol="tcp", dst_port=8443,
                       source_origin="opnsense:x", external_id="u-real",
                       src_interface="WAN", disabled=False),
    ])
    await db_session.flush()
    items = [i for i in await detect_fw_rule_rot(db_session) if i["kind"] == "dangling_nat"]
    names = {i["name"] for i in items}
    assert "Anti-Lockout Rule" not in names, "防火牆自動產生的防鎖死規則被當成懸空轉發"
    assert "to-alias" not in names, "目標是別名的轉發不是懸空"
    real = next(i for i in items if i["name"] == "real-dangling")
    assert real["interface"] == "WAN", "要看得出是哪個介面上的轉發"


@pytest.mark.anyio
async def test_dangling_nat_names_the_firewall(db_session) -> None:
    """同名規則可能來自好幾台防火牆：每一列要帶出是哪一台。"""
    from app.models.firewall import OPNsenseFirewall

    fw = OPNsenseFirewall(name=f"opn-{uuid.uuid4().hex[:6]}", api_url="https://192.0.2.1",
                          api_key_enc=b"x", api_key_nonce=b"y",
                          api_secret_enc=b"x", api_secret_nonce=b"y")
    db_session.add(fw)
    await db_session.flush()
    db_session.add(NATTranslation(name="fw-named", type="port_forward", protocol="tcp",
                                  dst_port=8080, source_origin=f"opnsense:{fw.id}",
                                  external_id="u-fw", disabled=False))
    await db_session.flush()
    items = await detect_fw_rule_rot(db_session)
    row = next(i for i in items if i.get("name") == "fw-named")
    assert row["firewall"] == fw.name


@pytest.mark.anyio
async def test_any_any_ignores_protocol_or_port_limited_rules(db_session) -> None:
    """any → any 只算「任何協定、任何埠」都放行的規則。

    正式環境曾把 WAN 上一條「只放行 ICMP（ping）」的規則報成「等於這個介面沒有防火牆」。
    """
    from app.models.pfsense import PfSenseFirewall

    fw = PfSenseFirewall(name=f"pf-{uuid.uuid4().hex[:6]}", api_url="https://192.0.2.4",
                         api_key_enc=b"x", api_key_nonce=b"y",
                         rules=[
                             _pf_rule(interface="wan", protocol="icmp", descr="ping only"),
                             _pf_rule(interface="lan", protocol="tcp", destination_port="443",
                                      descr="https only"),
                             _pf_rule(interface="openvpn", protocol=None, descr="vpn all"),
                             _pf_rule(interface="opt1", protocol="tcp/udp", descr="all tcp udp"),
                         ])
    db_session.add(fw)
    await db_session.flush()
    rows = [i for i in await detect_fw_rule_rot(db_session)
            if i["kind"] == "any_any" and i.get("firewall") == fw.name]
    descrs = {i.get("descr") for i in rows}
    assert "ping only" not in descrs, "只放行 ICMP 不等於沒有防火牆"
    assert "https only" not in descrs, "限定目的埠的規則不是 any → any"
    assert {"vpn all", "all tcp udp"} <= descrs
