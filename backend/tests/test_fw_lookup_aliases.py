"""IP 詳細頁的「所屬別名」：要看得出是哪一台防火牆的別名。

規則那幾行都寫著防火牆名稱（fw-01｜pass …），別名卻只有名稱與廠牌 ——
有兩台 OPNsense 時，看不出 `web_hosts` 是哪一台上的。MikroTik 以前還用清單名稱
去重：兩台路由器剛好都有同名清單時只剩一筆，另一台就消失了。
"""
from __future__ import annotations

import pytest
from app.services.fw_lookup import rules_touching_ip


@pytest.mark.anyio
async def test_aliases_carry_the_firewall_name(db_session) -> None:
    from app.models.firewall import OPNsenseFirewall, OPNsenseSyncedAlias
    from app.models.mikrotik import MikroTikAddressList, MikroTikRouter
    from app.models.pfsense import PfSenseFirewall, PfSenseSyncedAlias

    opn = OPNsenseFirewall(name="opn-a", api_url="https://192.0.2.1",
                           api_key_enc=b"x", api_key_nonce=b"y",
                           api_secret_enc=b"x", api_secret_nonce=b"y")
    pf = PfSenseFirewall(name="pf-b", api_url="https://192.0.2.2",
                         api_key_enc=b"x", api_key_nonce=b"y")
    r1 = MikroTikRouter(name="mt-c", api_url="https://192.0.2.3", api_username="u",
                        api_password_enc=b"x", api_password_nonce=b"y")
    r2 = MikroTikRouter(name="mt-d", api_url="https://192.0.2.4", api_username="u",
                        api_password_enc=b"x", api_password_nonce=b"y")
    db_session.add_all([opn, pf, r1, r2])
    await db_session.flush()
    db_session.add_all([
        OPNsenseSyncedAlias(firewall_id=opn.id, name="web_servers", alias_type="host",
                            enabled=True, content=["198.51.100.50"], description="public web"),
        PfSenseSyncedAlias(firewall_id=pf.id, name="pf_hosts", alias_type="host",
                           members=["198.51.100.50"]),
        # 兩台路由器都有同名清單 —— 兩台都要列出來
        MikroTikAddressList(router_id=r1.id, list_name="trusted", address="198.51.100.50"),
        MikroTikAddressList(router_id=r2.id, list_name="trusted", address="198.51.100.0/24"),
    ])
    await db_session.flush()

    out = await rules_touching_ip(db_session, "198.51.100.50")
    got = {(a["source_type"], a["firewall"], a["name"]) for a in out["aliases"]}
    assert ("opnsense", "opn-a", "web_servers") in got
    assert ("pfsense", "pf-b", "pf_hosts") in got
    assert ("mikrotik", "mt-c", "trusted") in got
    assert ("mikrotik", "mt-d", "trusted") in got, "同名清單在另一台路由器上被去重吃掉了"
    web = next(a for a in out["aliases"] if a["name"] == "web_servers")
    assert web["descr"] == "public web"


@pytest.mark.anyio
async def test_mikrotik_list_rules_are_found_through_the_list(db_session) -> None:
    """MikroTik 的 address-list 要反查得到（`list:<清單名>` 的規則也靠它命中）。

    address 是單一字串，以前直接傳給「成員清單」比對 → 逐字元比，永遠比不到，
    所以這類規則在 IP 詳細頁從來沒出現過。"""
    from app.models.mikrotik import MikroTikAddressList, MikroTikRouter

    r = MikroTikRouter(name="mt-e", api_url="https://192.0.2.5", api_username="u",
                       api_password_enc=b"x", api_password_nonce=b"y")
    db_session.add(r)
    await db_session.flush()
    db_session.add(MikroTikAddressList(router_id=r.id, list_name="web", address="198.51.100.60"))
    await db_session.flush()
    out = await rules_touching_ip(db_session, "198.51.100.60")
    assert [(a["firewall"], a["name"]) for a in out["aliases"]] == [("mt-e", "web")]


@pytest.mark.anyio
async def test_fortigate_and_paloalto_address_objects_and_the_policies_using_them(db_session) -> None:
    """FortiGate／Palo Alto 的政策以物件名稱引用（而且常常好幾個串在同一欄）：以前只比對位址字面值，
    以物件引用的政策一條都反查不到，位址物件本身也不會出現在「所屬別名」（2026-10-05，調查加強時發現）。"""
    from app.models.fortigate import FortiGateAddressObject, FortiGateFirewall, FortiGatePolicy
    from app.models.paloalto import PaloAltoAddressObject, PaloAltoFirewall, PaloAltoPolicy

    ip = "198.51.100.70"
    fg = FortiGateFirewall(name="fg-a", api_url="https://192.0.2.10", api_token_enc=b"x", api_token_nonce=b"y")
    fg2 = FortiGateFirewall(name="fg-b", api_url="https://192.0.2.11", api_token_enc=b"x", api_token_nonce=b"y")
    pa = PaloAltoFirewall(name="pa-a", api_url="https://192.0.2.12", api_key_enc=b"x", api_key_nonce=b"y")
    db_session.add_all([fg, fg2, pa])
    await db_session.flush()
    db_session.add_all([
        FortiGateAddressObject(firewall_id=fg.id, name="srv-70", kind="address", obj_type="ipmask",
                               value=f"{ip}/255.255.255.255", comment="app server"),
        FortiGateAddressObject(firewall_id=fg.id, name="servers", kind="group", obj_type="addrgrp",
                               members=["srv-70", "srv-71"]),
        FortiGateAddressObject(firewall_id=fg.id, name="all", kind="address", obj_type="ipmask",
                               value="0.0.0.0/0.0.0.0"),
        FortiGateAddressObject(firewall_id=fg.id, name="fqdn-x", kind="address", obj_type="fqdn",
                               value="x.example.com"),
        FortiGatePolicy(firewall_id=fg.id, policyid="3", name="to-servers", action="accept",
                        srcaddr="all", dstaddr="lan-net, servers"),
        # 另一台防火牆剛好有同名物件，但不是指這個位址：不可以因為名稱一樣就命中
        FortiGateAddressObject(firewall_id=fg2.id, name="other", kind="address", value="203.0.113.1/32"),
        FortiGatePolicy(firewall_id=fg2.id, policyid="4", name="fg2-servers", action="accept",
                        srcaddr="all", dstaddr="servers"),
        PaloAltoAddressObject(firewall_id=pa.id, name="range-70", kind="address", obj_type="ip-range",
                              value="198.51.100.64-198.51.100.79"),
        PaloAltoPolicy(firewall_id=pa.id, name="allow-range", action="allow", source="any",
                       destination="range-70"),
    ])
    await db_session.flush()

    out = await rules_touching_ip(db_session, ip)
    aliases = {(a["firewall"], a["name"]) for a in out["aliases"]}
    assert aliases == {("fg-a", "srv-70"), ("fg-a", "servers"), ("pa-a", "range-70")}
    assert next(a for a in out["aliases"] if a["name"] == "srv-70")["descr"] == "app server"
    rules = {(r["firewall"], r["descr"]) for r in out["rules"]}
    assert ("fg-a", "to-servers") in rules
    assert ("pa-a", "allow-range") in rules
    assert ("fg-b", "fg2-servers") not in rules
