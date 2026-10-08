"""Zabbix 整合：定位、對應安全與涵蓋缺口。

Zabbix 的定位是**監控面補充**，因此測試守的是三件事：
- 只標既有 IP、不新建（自動收錄會讓「未授權 IP」那道訊號失效）
- 重疊網段下不可誤掛（限定範圍 + limit(1)，不可用 scalar_one_or_none）
- 多台主機指向同一 IP 時要穩定收斂（Wazuh 漏了這個，十天洗出 620 筆翻動）
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.zabbix import ZabbixHost, ZabbixInstance
from app.services.zabbix import _first_ip, _rpc_url, coverage_gap


def test_rpc_url_accepts_common_forms() -> None:
    """使用者會填 https://host、https://host/zabbix，或完整路徑 —— 三種都要能用。"""
    assert _rpc_url("https://zbx.example.net") == "https://zbx.example.net/api_jsonrpc.php"
    assert _rpc_url("https://zbx.example.net/zabbix/") == \
        "https://zbx.example.net/zabbix/api_jsonrpc.php"
    assert _rpc_url("https://zbx.example.net/api_jsonrpc.php") == \
        "https://zbx.example.net/api_jsonrpc.php"


def test_first_ip_prefers_valid_address_and_keeps_dns() -> None:
    ip, dns = _first_ip([{"ip": "", "dns": "host.example.net"},
                         {"ip": "198.51.100.9", "dns": ""}])
    assert (ip, dns) == ("198.51.100.9", "host.example.net")
    # Zabbix 可能填非位址字串（例如空或 {$MACRO}）→ 不可讓它進到 INET 欄位
    assert _first_ip([{"ip": "{$HOST.IP}", "dns": "x.example.net"}]) == \
        (None, "x.example.net")


async def _fixture(session):
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    session.add(sec)
    await session.flush()
    a = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    b = Subnet(section_id=sec.id, cidr="203.0.113.0/24")
    session.add_all([a, b])
    await session.flush()
    ips = [
        IPAddress(subnet_id=a.id, ip="198.51.100.10", hostname="in-scope", state="used"),
        IPAddress(subnet_id=b.id, ip="203.0.113.10", hostname="other", state="used"),
    ]
    session.add_all(ips)
    await session.flush()
    inst = ZabbixInstance(name=f"zbx-{uuid.uuid4().hex[:6]}",
                          api_url="https://192.0.2.40", scope_subnet_ids=[str(a.id)])
    session.add(inst)
    await session.flush()
    return inst, a, b, ips


@pytest.mark.anyio
async def test_coverage_gap_is_scoped(db_session) -> None:
    """涵蓋缺口一定要能限定網段，否則問某網段會拿到全站答案（v0.5.194 的教訓）。"""
    inst, a, b, ips = await _fixture(db_session)
    db_session.add(ZabbixHost(instance_id=inst.id, hostid="1", host="in-scope",
                              status="monitored", jt_ipam_address_id=ips[0].id))
    await db_session.flush()

    scoped = await coverage_gap(db_session, instance_id=inst.id, subnet_ids=[a.id])
    assert scoped == [], "已被監控的位址不該出現在缺口清單"

    other = await coverage_gap(db_session, instance_id=inst.id, subnet_ids=[b.id])
    assert [r["hostname"] for r in other] == ["other"]

    empty = await coverage_gap(db_session, instance_id=inst.id, subnet_ids=[])
    assert empty == [], "空範圍要回空，不可退化成全域"


@pytest.mark.anyio
async def test_unmonitored_host_counts_as_gap(db_session) -> None:
    """Zabbix 裡存在但停用監控的主機，等於沒被監控 —— 必須列入缺口。"""
    inst, a, _b, ips = await _fixture(db_session)
    db_session.add(ZabbixHost(instance_id=inst.id, hostid="2", host="paused",
                              status="unmonitored", jt_ipam_address_id=ips[0].id))
    await db_session.flush()
    gap = await coverage_gap(db_session, instance_id=inst.id, subnet_ids=[a.id])
    assert [r["hostname"] for r in gap] == ["in-scope"]


def test_zabbix_is_a_registered_hostname_source() -> None:
    """來源沒登記會被靜默改成 manual（Windows DHCP 那次踩過）。"""
    from app.models.ip_hostname import HOSTNAME_SOURCES

    assert "zabbix" in HOSTNAME_SOURCES


def test_transfer_registry_covers_new_tables() -> None:
    from app.services.system_transfer import registry

    assert registry.validate_registry() == [], "新表未分類 → 跨機搬移會靜靜掉資料"


def test_availability_reads_from_interface_on_6_plus() -> None:
    """6.0 移除了 `host.available`，可用性改掛在介面上。

    這條是「沒有實機也要守住」的那種差異：搞錯不是少一個欄位，而是整批同步失敗。
    """
    from app.services.zabbix import _availability, _major

    assert _availability({"available": "1"}) == "up"          # 5.x：主機層
    assert _availability({"interfaces": [{"available": "2"},   # 6.x：介面層
                                          {"available": "1"}]}) == "up"
    assert _availability({"interfaces": [{"available": "2"}]}) == "down"
    assert _availability({"interfaces": [{"ip": "198.51.100.1"}]}) == "unknown"
    assert _major("6.0.28") == 6
    assert _major("7.0.0") == 7
    assert _major(None) == 0                                   # 解析不出來 → 走舊版路徑
