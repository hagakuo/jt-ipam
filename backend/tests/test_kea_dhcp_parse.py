"""issue #45（使用者追加）：獨立的 Kea DHCP Server —— 經 Kea 的 JSON 控制 API 拉取。

- 範圍與保留：`config-get`（subnet4／shared-networks 底下的 subnet4；pool 可以寫成區間或 CIDR）
- 資料庫裡的保留（host_cmds）：`reservation-get-all`，不支援就只用設定檔裡的
- 租約（lease_cmds）：`lease4-get-page` 分頁；只算 state=0（已指派）且還沒到期的
- 控制代理（kea-ctrl-agent）回的是清單、要帶 service；Kea 3.0 直接連 DHCP 伺服器回的是單一物件
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app.services import kea_dhcp as kea

DHCP4 = {
    "subnet4": [
        {"id": 1, "subnet": "192.0.2.0/24",
         "pools": [{"pool": "192.0.2.100 - 192.0.2.150"}, {"pool": "192.0.2.192/27"}],
         "reservations": [
             {"hw-address": "00:00:5E:00:53:01", "ip-address": "192.0.2.5", "hostname": "printer-1"},
             {"client-id": "01:02:03", "ip-address": "192.0.2.6"},
             {"hw-address": "00:00:5e:00:53:09", "hostname": "no-ip-only-options"},
         ]},
    ],
    "shared-networks": [
        {"name": "campus", "subnet4": [
            {"id": 2, "subnet": "198.51.100.0/25", "pools": [{"pool": "198.51.100.10-198.51.100.20"}]},
        ]},
    ],
    # 全域保留通常沒有位址（只給選項）；有位址的才算
    "reservations": [{"hw-address": "00:00:5e:00:53:07", "ip-address": "203.0.113.7", "hostname": "global-7"}],
}


def test_config_pools_and_reservations() -> None:
    pools, res, subnet_ids = kea.parse_config(DHCP4)
    assert pools == [
        {"subnet": "192.0.2.0/24", "start": "192.0.2.100", "end": "192.0.2.150"},
        {"subnet": "192.0.2.0/24", "start": "192.0.2.192", "end": "192.0.2.223"},
        {"subnet": "198.51.100.0/25", "start": "198.51.100.10", "end": "198.51.100.20"},
    ]
    assert res == [
        {"ip": "192.0.2.5", "mac": "00:00:5e:00:53:01", "hostname": "printer-1", "subnet": "192.0.2.0/24"},
        {"ip": "192.0.2.6", "mac": None, "hostname": None, "subnet": "192.0.2.0/24"},
        {"ip": "203.0.113.7", "mac": "00:00:5e:00:53:07", "hostname": "global-7", "subnet": None},
    ]
    assert subnet_ids == {1: "192.0.2.0/24", 2: "198.51.100.0/25"}


def test_bad_pool_strings_are_skipped_not_fatal() -> None:
    pools, _, _ = kea.parse_config({"subnet4": [{"id": 9, "subnet": "192.0.2.0/24",
                                                 "pools": [{"pool": "garbage"}, {"pool": "192.0.2.9 - x"}]}]})
    assert pools == []


def test_leases_only_assigned_and_unexpired() -> None:
    now = datetime(2026, 9, 28, 4, 0, tzinfo=UTC)
    t = int(now.timestamp())
    got = kea.parse_leases([
        {"ip-address": "192.0.2.101", "hw-address": "00:00:5e:00:53:11", "hostname": "laptop-11",
         "state": 0, "cltt": t - 600, "valid-lft": 3600, "subnet-id": 1},
        {"ip-address": "192.0.2.102", "hw-address": "00:00:5e:00:53:12", "state": 0,
         "cltt": t - 7200, "valid-lft": 3600},                    # 已過期
        {"ip-address": "192.0.2.103", "hw-address": "00:00:5e:00:53:13", "state": 1,
         "cltt": t, "valid-lft": 3600},                           # declined
        {"ip-address": "192.0.2.104", "hw-address": "", "state": 2, "cltt": t, "valid-lft": 3600},  # reclaimed
        {"ip-address": "192.0.2.105", "state": 0, "cltt": t - 10, "valid-lft": 4294967295},       # 無限
    ], now=now)
    assert [x["ip"] for x in got] == ["192.0.2.101", "192.0.2.105"]
    assert got[0]["mac"] == "00:00:5e:00:53:11" and got[0]["hostname"] == "laptop-11"
    assert got[0]["ends"] == "2026-09-28T04:50:00+00:00"
    assert got[1]["ends"] is None


@pytest.mark.parametrize("raw,expected", [
    ([{"result": 0, "arguments": {"Dhcp4": {}}}], {"Dhcp4": {}}),          # 控制代理：清單
    ({"result": 0, "arguments": {"Dhcp4": {}}}, {"Dhcp4": {}}),            # Kea 3.0 直連：單一物件
    ([{"result": 3, "text": "0 IPv4 lease(s) found."}], {}),              # 沒有資料不是錯誤
])
def test_response_normalisation(raw, expected) -> None:
    assert kea.unwrap(raw, "config-get") == expected


def test_unsupported_and_error_are_distinguished() -> None:
    with pytest.raises(kea.KeaUnsupported):
        kea.unwrap([{"result": 2, "text": "'lease4-get-page' command not supported."}], "lease4-get-page")
    with pytest.raises(kea.KeaError) as ei:
        kea.unwrap([{"result": 1, "text": "unable to forward command to the dhcp4 service"}], "config-get")
    assert "unable to forward" in str(ei.value), "錯誤要帶 Kea 回的原文"
