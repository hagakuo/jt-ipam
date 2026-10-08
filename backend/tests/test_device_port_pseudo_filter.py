"""LibreNMS 埠匯入要濾掉 Windows 端點的偽介面。

由來（2026-09-18 使用者回報，附截圖）：win11 的裝置埠清單出現 ethernet_3 / ethernet_5 /
ethernet_32772 / ppp_32769，全都複製同一張實體卡的 MAC，對 IPAM 佈線毫無意義。這些是
LibreNMS 從 Windows 的 ifIndex 產生的名稱（NDIS 輕量過濾器、WAN Miniport、通道），真正
的實體卡會保有友善名稱（乙太網路、Wi-Fi）。交換器與 Linux 的埠名不會長這樣，不受影響。
"""

from __future__ import annotations

import re

import pytest

from app.api.v1.endpoints.physical import _is_pseudo_iface


def test_windows_pseudo_names_are_dropped() -> None:
    for n in ("ethernet_3", "ethernet_5", "ethernet_8", "ethernet_32772",
              "wireless_0", "wireless_32768", "ppp_32769", "ppp_32768",
              "tunnel_2", "ETHERNET_10"):
        assert _is_pseudo_iface(n), n


def test_real_port_names_are_kept() -> None:
    # Windows 友善名、Linux、交換器、PVE bridge —— 都要保留
    for n in ("乙太網路", "乙太網路 2", "Wi-Fi", "eth0", "ens18", "bond0", "vmbr0",
              "GigabitEthernet0/1", "Gi1/0/24", "Local Area Connection", "eth1/0/24"):
        assert not _is_pseudo_iface(n), n


def test_pseudo_iftypes_are_dropped_even_with_friendly_name() -> None:
    assert _is_pseudo_iface("WAN Miniport", "ppp")
    assert _is_pseudo_iface("lo0", "softwareLoopback")
    assert not _is_pseudo_iface("port1", "ethernetCsmacd")



def test_is_pseudo_iface_honors_custom_patterns() -> None:
    """帶入自訂樣式時只依自訂樣式判斷（管理者可調整清單）。"""
    pats = [re.compile(r"^vmbr\d+$", re.IGNORECASE)]
    assert _is_pseudo_iface("vmbr0", None, pats)
    assert not _is_pseudo_iface("ethernet_3", None, pats)   # 不在自訂清單內


@pytest.mark.anyio
async def test_device_port_filter_setting_roundtrip(db_session) -> None:
    from app.services.system_config import (
        DEFAULT_PORT_IGNORE_PATTERNS, get_device_port_filter, set_device_port_filter,
    )
    # 預設：開、用內建清單
    cfg = await get_device_port_filter(db_session)
    assert cfg["filter_pseudo"] is True
    assert cfg["ignore_patterns"] == DEFAULT_PORT_IGNORE_PATTERNS
    # 存自訂：壞正則被丟掉、空清單退回預設、去重
    await set_device_port_filter(
        db_session, filter_pseudo=False,
        ignore_patterns=[r"^vmbr\d+$", "([bad", r"^vmbr\d+$", "  "])
    cfg = await get_device_port_filter(db_session)
    assert cfg["filter_pseudo"] is False
    assert cfg["ignore_patterns"] == [r"^vmbr\d+$"]
    # 全空 → 退回預設
    await set_device_port_filter(db_session, filter_pseudo=True, ignore_patterns=[])
    cfg = await get_device_port_filter(db_session)
    assert cfg["ignore_patterns"] == DEFAULT_PORT_IGNORE_PATTERNS


@pytest.mark.anyio
async def test_device_port_filter_endpoint(client, auth_headers) -> None:
    r = await client.get("/api/v1/system/device-port-filter", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["filter_pseudo"] is True
    r = await client.put("/api/v1/system/device-port-filter", headers=auth_headers,
                         json={"filter_pseudo": False, "ignore_patterns": [r"^dummy\d+$"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["filter_pseudo"] is False and body["ignore_patterns"] == [r"^dummy\d+$"]
