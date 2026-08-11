"""RDAP 匯入：解析、輸入驗證、以及「錯誤要分對類別」。

不打真的網路 —— 用實際抓回來的 RDAP 回應樣本測解析（樣本取自 twnic.rdap.apnic.net
與 rdap.db.ripe.net，2026-08-01）。
"""

from __future__ import annotations

import pytest
from app.services.rdap import (
    RdapError,
    RdapInputError,
    normalize_query,
    parse_rdap_network,
)

# twnic.rdap.apnic.net/ip/163.28.0.0 的實際回應（節錄）
_TWNIC = {
    "handle": "163.28.0.0 - 163.28.255.255",
    "startAddress": "163.28.0.0", "endAddress": "163.28.255.255",
    "name": "T-EDU.TW-NET", "country": "TW", "type": "ASSIGNED NON-PORTABLE",
    "status": ["active"], "ipVersion": "v4",
    "cidr0_cidrs": [{"v4prefix": "163.28.0.0", "length": 16}],
    "remarks": [{"description": ["Ministry of Education Computer Center", "Taipei Taiwan"]}],
    "entities": [{
        "handle": "AM5-TW", "roles": ["administrative", "technical"],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                 ["fn", {}, "text", "Admin MOECC"]]],
    }],
}


def test_parse_twnic_network():
    net = parse_rdap_network(_TWNIC)
    assert net.cidrs == ["163.28.0.0/16"]
    assert net.name == "T-EDU.TW-NET"
    assert net.country == "TW"
    assert net.net_type == "ASSIGNED NON-PORTABLE"
    assert net.status == ["active"]
    assert "Ministry of Education Computer Center" in net.remarks
    assert net.entities[0]["handle"] == "AM5-TW"
    assert net.entities[0]["name"] == "Admin MOECC"          # 從 jCard 的 fn 取出
    assert net.entities[0]["roles"] == ["administrative", "technical"]


def test_cidr_falls_back_to_address_range():
    """沒有 cidr0_cidrs 時要由起訖位址推 —— 不是每家註冊管理機構都回這個擴充欄位。"""
    d = {k: v for k, v in _TWNIC.items() if k != "cidr0_cidrs"}
    assert parse_rdap_network(d).cidrs == ["163.28.0.0/16"]


def test_range_not_on_cidr_boundary_expands_to_several():
    d = {"startAddress": "192.0.2.0", "endAddress": "192.0.2.191"}
    assert parse_rdap_network(d).cidrs == ["192.0.2.0/25", "192.0.2.128/26"]


def test_parse_tolerates_missing_and_malformed_fields():
    """對方少給欄位不能整個炸掉 —— 各家 RDAP 的完整度不一。"""
    net = parse_rdap_network({})
    assert net.cidrs == []
    assert net.name is None
    assert net.entities == []
    bad = parse_rdap_network({"cidr0_cidrs": [{"v4prefix": "not-an-ip", "length": 16}, {}],
                              "entities": [{"vcardArray": "wrong-shape"}]})
    assert bad.cidrs == []
    assert bad.entities[0]["name"] is None


@pytest.mark.parametrize(("raw", "expect"), [
    ("163.28.0.0", "163.28.0.0"),
    (" 1.34.0.0/16 ", "1.34.0.0/16"),
    ("2001:db8::/32", "2001:db8::/32"),
    ("192.0.2.5/24", "192.0.2.0/24"),          # strict=False：主機位元照樣接受
])
def test_normalize_accepts_addresses_and_networks(raw, expect):
    assert normalize_query(raw) == expect


@pytest.mark.parametrize("raw", ["example.com", "'; DROP TABLE--", "../../etc/passwd", "", "  ",
                                 "163.28.0.0 163.28.0.1"])
def test_normalize_rejects_anything_not_an_address(raw):
    """這個值會被接進查詢網址，只能放真的位址 —— 其餘一律擋掉。"""
    with pytest.raises(RdapInputError):
        normalize_query(raw)


def test_input_error_is_distinguishable_from_upstream_error():
    """端點靠這個分辨要回 400 還是 502；若不是子類別就會把使用者打錯字回報成上游故障。"""
    assert issubclass(RdapInputError, RdapError)
    with pytest.raises(RdapError):        # 仍可用父類別攔截
        normalize_query("nope")
