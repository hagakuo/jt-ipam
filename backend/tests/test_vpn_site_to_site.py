"""站對站 VPN 畫上拓樸圖：FortiGate、Palo Alto、MikroTik（2026-10-01 使用者要求）。

以前只有 OPNsense 的通道會記「這條是哪一台的」（a_device_id）並配對到對端；FortiGate 有抓 IPsec
卻沒記本機裝置，Palo Alto 根本沒抓，MikroTik 的 WireGuard 沒記本機也沒有本機公鑰 —— 拓樸圖
畫通道至少要知道一端是哪台裝置，所以這些通道從沒出現過。

配對沿用既有規則：WireGuard 用公鑰（可靠）、IPsec 用端點位址（best-effort：對端閘道位址正好是
另一台已知防火牆的位址才連）。跨廠牌也成立 —— FortiGate 的對端是 Palo Alto 的 WAN 位址。
"""
from __future__ import annotations

import httpx
import pytest
from app.models.address import IPAddress
from app.models.device import Device
from app.models.physical import VPNTunnel
from app.models.section import Section
from app.models.subnet import Subnet
from sqlalchemy import select

_FLOW = """<response status="success"><result>
<dp>dp0</dp><total>2</total><num_ipsec>2</num_ipsec><num_sslvpn>0</num_sslvpn>
<IPSec>
<entry><name>to-hq</name><id>1</id><gwid>1</gwid><inner-if>tunnel.1</inner-if><outer-if>ethernet1/1</outer-if>
<localip>203.0.113.9</localip><peerip>198.51.100.7</peerip><state>active</state><mon>off</mon><owner>1</owner></entry>
<entry><name>to-dr</name><id>2</id><gwid>2</gwid><inner-if>tunnel.2</inner-if><outer-if>ethernet1/1</outer-if>
<localip>203.0.113.9</localip><peerip>192.0.2.200</peerip><state>init</state><mon>off</mon><owner>1</owner></entry>
</IPSec></result></response>"""


async def _devices(db) -> dict[str, Device]:
    """FortiGate（管理位址 192.0.2.1）、Palo Alto（192.0.2.2）兩台裝置與它們的管理 IP。"""
    sec = Section(name="vpn-s2s")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="192.0.2.0/24")
    db.add(sub)
    await db.flush()
    out = {}
    for name, ip in (("fgt-hq", "192.0.2.1"), ("pa-branch", "192.0.2.2"), ("ccr-dc", "192.0.2.3")):
        d = Device(name=name, type="firewall")
        db.add(d)
        await db.flush()
        db.add(IPAddress(subnet_id=sub.id, ip=ip, device_id=d.id))
        out[name] = d
    await db.flush()
    return out


async def _palo(db, name: str = "pa-branch", url: str = "https://192.0.2.2"):
    from app.models.paloalto import PaloAltoFirewall
    from app.services import paloalto as pa
    fw = PaloAltoFirewall(name=name, api_url=url, api_key_enc=b"x", api_key_nonce=b"x")
    db.add(fw)
    await db.flush()
    fw.api_key_enc, fw.api_key_nonce = pa.encrypt_api_key(fw.id, "k")
    await db.flush()
    return fw


def _patch_pa_xml(monkeypatch, body: str) -> list[str]:
    from app.services import paloalto as pa
    seen: list[str] = []

    async def fake(_fw, *, path, params, timeout=15.0):  # type: ignore[no-untyped-def]
        seen.append(params.get("cmd", ""))
        return httpx.Response(200, text=body)
    monkeypatch.setattr(pa, "_request", fake)
    return seen


@pytest.mark.anyio
async def test_palo_alto_ipsec_tunnels_are_mirrored(db_session, monkeypatch) -> None:
    from app.services import paloalto as pa
    devs = await _devices(db_session)
    fw = await _palo(db_session)
    cmds = _patch_pa_xml(monkeypatch, _FLOW)
    out = await pa.sync_vpn(db_session, fw)
    assert out["tunnels"] == 2
    assert any("<vpn><flow>" in c for c in cmds)
    tuns = {t.name: t for t in (await db_session.execute(select(VPNTunnel))).scalars().all()}
    hq = tuns["pa-branch/ipsec/to-hq"]
    assert (hq.status, hq.a_endpoint, hq.b_endpoint) == ("active", "203.0.113.9", "198.51.100.7")
    assert hq.a_device_id == devs["pa-branch"].id                 # API 位址對到的裝置
    assert hq.source_origin == f"paloalto:{fw.id}"
    assert tuns["pa-branch/ipsec/to-dr"].status == "offline"     # init＝還沒建立

    # 下一輪少了一條 → 清掉
    one = _FLOW[:_FLOW.index("<entry><name>to-dr</name>")] + "</IPSec></result></response>"
    _patch_pa_xml(monkeypatch, one)
    await pa.sync_vpn(db_session, fw)
    names = {t.name for t in (await db_session.execute(select(VPNTunnel))).scalars().all()}
    assert names == {"pa-branch/ipsec/to-hq"}


@pytest.mark.anyio
async def test_fortigate_tunnel_knows_its_device_and_pairs_with_palo_alto(db_session, monkeypatch) -> None:
    """FortiGate 的對端閘道（rgwy）＝Palo Alto 通道記的本機位址 → 跨廠牌配對，拓樸圖畫出兩台之間的 VPN。"""
    from app.models.fortigate import FortiGateFirewall
    from app.services import fortigate as fg
    from app.services import paloalto as pa
    from app.services.topology import build_topology

    devs = await _devices(db_session)
    pfw = await _palo(db_session)
    _patch_pa_xml(monkeypatch, _FLOW.replace("198.51.100.7", "198.51.100.1"))
    await pa.sync_vpn(db_session, pfw)

    ffw = FortiGateFirewall(name="fgt-hq", api_url="https://192.0.2.1", api_token_enc=b"x",
                            api_token_nonce=b"x", vdoms=["root"])
    db_session.add(ffw)
    await db_session.flush()

    async def fake(_fw, path, *, vdom=None, timeout=15.0):  # type: ignore[no-untyped-def]
        if path == fg.EP_VPN_IPSEC:
            return [{"name": "to-branch", "rgwy": "203.0.113.9", "proxyid": [{"status": "up"}]}]
        return []
    monkeypatch.setattr(fg, "_api_get", fake)
    await fg.sync_vpn(db_session, ffw, ["root"])
    await db_session.flush()

    t = (await db_session.execute(select(VPNTunnel).where(VPNTunnel.name == "fgt-hq/ipsec/root/to-branch"))).scalar_one()
    assert t.a_device_id == devs["fgt-hq"].id
    assert t.b_device_id == devs["pa-branch"].id
    assert t.pairing_method == "ipsec_endpoint"
    await db_session.commit()

    g = await build_topology(db_session, include_wireless=False, include_l3=False)
    vpn = [e["data"] for e in g["edges"] if e["data"].get("kind") == "vpn"]
    pair = {str(devs["fgt-hq"].id), str(devs["pa-branch"].id)}
    assert any({e["source"], e["target"]} == pair for e in vpn), vpn


@pytest.mark.anyio
async def test_mikrotik_wireguard_knows_its_device_and_local_key(db_session, monkeypatch) -> None:
    """MikroTik 的 WireGuard 通道記本機裝置與本機公鑰 → 能用公鑰和 OPNsense 那端配對。"""
    from app.models.mikrotik import MikroTikRouter
    from app.services import mikrotik as svc
    from app.services.vpn_pairing import link_peers

    from tests.test_mikrotik import _fake_client, _MenuTransport
    devs = await _devices(db_session)
    router = MikroTikRouter(name="ccr-dc", api_url="https://192.0.2.3", api_username="u", api_password_enc=b"x",
                            api_password_nonce=b"y", section_delay_ms=0, cpu_load_limit=0, sync_firewall=False,
                            sync_nat=False, sync_dhcp=False, sync_dhcp_ranges=False, sync_vpn=True,
                            sync_address_lists=False, sync_arp=False, sync_interfaces=False,
                            sync_neighbors=False, sync_fdb=False)
    db_session.add(router)
    # OPNsense 那端（已同步進來的樣子）：本機公鑰 OPN=、對端公鑰 MT=
    db_session.add(VPNTunnel(name="fw-x/wg/to-dc", type="wireguard", a_device_id=devs["fgt-hq"].id,
                             local_public_key="OPN=", peer_public_key="MT=", b_endpoint="203.0.113.30"))
    await db_session.flush()
    _fake_client(monkeypatch, _MenuTransport({
        "/ppp/active": [],
        "/interface/wireguard": [{"name": "wg-hq", "public-key": "MT=", "listen-port": "13231"}],
        "/interface/wireguard/peers": [{"interface": "wg-hq", "name": "hq", "public-key": "OPN=",
                                        "endpoint-address": "198.51.100.1", "last-handshake": "30s"}],
    }, cpu_seq=[5]))
    from app.services import vpn_pairing
    monkeypatch.setattr(vpn_pairing, "link_peers", _noop)     # 先看同步本身寫了什麼
    await svc.sync_instance(db_session, router)
    await db_session.flush()
    t = (await db_session.execute(select(VPNTunnel).where(VPNTunnel.name == "ccr-dc/wireguard/wg-hq/hq"))).scalar_one()
    assert t.a_device_id == devs["ccr-dc"].id
    assert t.local_public_key == "MT="
    assert t.a_endpoint == "192.0.2.3"                       # 位址，不是整個 API 網址
    monkeypatch.undo()
    await link_peers(db_session)
    assert t.a_endpoint == "203.0.113.30"                    # 配對後換成對端看到的我方位址（WAN）
    assert t.b_device_id == devs["fgt-hq"].id
    assert t.pairing_method == "wireguard_pubkey"


async def _noop(_session) -> int:  # type: ignore[no-untyped-def]
    return 0
